package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"warden/internal/config"
)

func TestInitCustomLegacyMissingDBProtection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.json")
	db := filepath.Join(dir, "occupied.db")
	if e := os.WriteFile(db, []byte("existing identity"), 0600); e != nil {
		t.Fatal(e)
	}
	raw := []byte(`{"security":{"public_origin":"https://warden.example","rp_id":"warden.example","mode":"proxy","backend_authority":"127.0.0.1:8080"}}`)
	os.WriteFile(path, raw, 0600)
	old := checkInitializationStorage
	defer func() { checkInitializationStorage = old }()
	checkInitializationStorage = func(got string) error {
		if got != "/var/lib/warden/warden.db" {
			t.Fatal("lost legacy omitted path", got)
		}
		return freshInitializationStorage(db)
	}
	if _, _, e := promptInitialization(strings.NewReader("changed\n"), io.Discard, path); e == nil {
		t.Fatal("accepted initialized custom config")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, raw) {
		t.Fatal("rewrote initialized config")
	}
}
func TestInitCanonicalDraftPublication(t *testing.T) {
	for _, raw := range []string{`{"Initialization_Draft":true,"security":{}}`, `{"initialization_draft":true,"Initialization_Draft":false,"security":{}}`, `{"DB_PATH":"alias","security":{}}`} {
		path := filepath.Join(t.TempDir(), "custom.json")
		os.WriteFile(path, []byte(raw), 0600)
		if _, _, e := promptInitialization(strings.NewReader("changed\n"), io.Discard, path); e == nil {
			t.Fatal("alias accepted")
		}
		got, _ := os.ReadFile(path)
		if string(got) != raw {
			t.Fatal("alias rewritten")
		}
	}
}
func TestInitPublicationDurabilityBarrierBeforeSetup(t *testing.T) {
	for _, failure := range []bool{true, false} {
		t.Run(map[bool]string{true: "failure", false: "ordering"}[failure], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			db := filepath.Join(dir, "vault.db")
			old := synchronizeInitializationPublication
			defer func() { synchronizeInitializationPublication = old }()
			barrier, called := false, false
			sentinel := errors.New("fixture directory sync failure")
			synchronizeInitializationPublication = func(dir string) error {
				if dir != filepath.Dir(path) {
					t.Fatal("wrong directory", dir)
				}
				raw, _ := os.ReadFile(path)
				if !bytes.Contains(raw, []byte(`"initialization_draft"`)) {
					barrier = true
					if failure {
						return sentinel
					}
				}
				return nil
			}
			answers := db + "\nhttps://warden.example\nwarden.example\nproxy\n127.0.0.1:8080\n\n\n"
			_, _, e := initializeWithAnswers(strings.NewReader(answers), io.Discard, path, func(config.Server) error {
				called = true
				if !barrier {
					t.Fatal("setup before durability barrier")
				}
				return nil
			})
			if failure {
				if !errors.Is(e, sentinel) || called {
					t.Fatal("barrier failure did not stop setup", e, called)
				}
			} else if e != nil || !barrier || !called {
				t.Fatal("barrier ordering", e, barrier, called)
			}
		})
	}
}
