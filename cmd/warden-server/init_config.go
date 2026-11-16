package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"warden/internal/config"
)

// The config lease covers prompts AND the temporary setup plane. Keep the lock
// inode after close: unlinking it could permit two owners after a crash/retry.
// The DB reservation in setup remains independently authoritative for storage.
type initializationConfig struct {
	path     string
	lease    *os.File
	original []byte
	info     os.FileInfo
	fields   map[string]json.RawMessage
	cfg      config.Server
}

var checkInitializationStorage = freshInitializationStorage
var synchronizeInitializationPublication = syncInitializationDirectory

func readInitializationConfig(path string) (*initializationConfig, error) {
	s := &initializationConfig{path: path, fields: make(map[string]json.RawMessage), cfg: config.DefaultServer()}
	defaults := config.DefaultSetup()
	defaults.AuthMethod = "account"
	s.cfg.Security = &defaults
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("initialization config must be a regular file, not a symlink")
	}
	s.original, err = os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s.cfg, err = config.ParseServerDraft(path, s.original)
	if err != nil {
		return nil, err
	}
	if s.cfg.Security.AuthMethod == "" {
		s.cfg.Security.AuthMethod = "passkey"
	}
	// A draft has never been handed to setup or serve. It may contain an
	// occupied storage answer, which must remain correctable without opening it.
	// Published/legacy initialized configs may never be turned back into drafts.
	if !s.cfg.InitializationDraft {
		if err := checkInitializationStorage(s.cfg.DBPath); err != nil {
			return nil, err
		}
	}
	if err = json.Unmarshal(s.original, &s.fields); err != nil {
		return nil, err
	}
	s.info = info
	return s, nil
}

func openInitializationConfig(path string) (*initializationConfig, error) {
	// Refuse malformed/legacy/initialized configs before creating any artifact.
	if _, err := readInitializationConfig(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := syncInitializationAncestors(dir); err != nil {
		return nil, err
	}
	canonical := filepath.Join(dir, filepath.Base(path))
	lockPath := canonical + ".setup.lock"
	if info, err := os.Lstat(lockPath); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("initialization lock must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	lease, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockInitializationConfig(lease); err != nil {
		lease.Close()
		return nil, fmt.Errorf("initialization already running or unavailable: %w", err)
	}
	s, err := readInitializationConfig(canonical)
	if err != nil {
		lease.Close()
		return nil, err
	}
	s.lease = lease
	return s, nil
}

func freshInitializationStorage(path string) error {
	if path == "" {
		return nil
	} // Invalid answers are persisted before validation.
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			return errors.New("storage exists or is unavailable; preserve config/DB/WAL/SHM/key, export using old release if legacy, and run warden-server init with fresh storage")
		}
	}
	return nil
}

func (s *initializationConfig) unchanged() error {
	info, err := os.Lstat(s.path)
	if s.info == nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.New("initialization config changed; refusing to overwrite another writer")
	}
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, s.info) {
		return errors.New("initialization config changed; refusing to overwrite another writer")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, s.original) {
		return errors.New("initialization config changed; refusing to overwrite another writer")
	}
	return nil
}

func (s *initializationConfig) save() error {
	if err := s.unchanged(); err != nil {
		return err
	}
	// Keep all recognized non-prompted settings exactly as loaded; do not emit
	// DefaultServer's obsolete master-key fallback into a new configuration.
	for key, value := range map[string]any{"listen_addr": s.cfg.ListenAddr, "db_path": s.cfg.DBPath, "security": s.cfg.Security} {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		s.fields[key] = data
	}
	if s.cfg.InitializationDraft {
		s.fields["initialization_draft"] = json.RawMessage("true")
	} else {
		delete(s.fields, "initialization_draft")
	}
	data, err := json.MarshalIndent(s.fields, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".warden-config-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = s.unchanged(); err != nil {
		return err
	}
	if err = publishInitializationConfig(name, s.path, s.info != nil); err != nil {
		return err
	}
	// Identity commit must never run before the published config (especially draft
	// removal) crosses this barrier, even when config and DB are on different disks.
	if err = synchronizeInitializationPublication(filepath.Dir(s.path)); err != nil {
		return err
	}
	s.original = data
	s.info, err = os.Lstat(s.path)
	return err
}
