package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"warden/internal/model"
)

var connectionNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// validateJumpIDs verifies s is a syntactically valid JSON array of integer
// IDs. It does not check whether referenced ids exist: logical resolution is
// deferred to transport-query time.
func validateJumpIDs(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("jump_connection_ids must be a JSON array of integer ids")
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("jump_connection_ids: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '[' {
		return errors.New("jump_connection_ids must be a JSON array of integer ids")
	}

	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return fmt.Errorf("jump_connection_ids: %w", err)
		}
		num, ok := tok.(json.Number)
		if !ok {
			return fmt.Errorf("jump_connection_ids element %v is not an integer id", tok)
		}
		if _, err := strconv.ParseInt(num.String(), 10, 64); err != nil {
			return fmt.Errorf("jump_connection_ids element %q is not an integer id", num)
		}
	}

	closing, err := dec.Token()
	if err != nil {
		return fmt.Errorf("jump_connection_ids: %w", err)
	}
	if delim, ok := closing.(json.Delim); !ok || delim != ']' {
		return errors.New("jump_connection_ids must be a JSON array of integer ids")
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("jump_connection_ids must contain a single JSON array")
	}
	return nil
}

// parseJumpIDs parses a stored jump_connection_ids value. Rows are written
// through validateJumpIDs, so a parse failure here indicates external
// tampering; callers that need tolerance should treat it as "no jumps".
func parseJumpIDs(s string) ([]int64, error) {
	var ids []int64
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// validateGroupID checks a profile's group assignment inside the write
// transaction. Zero means ungrouped and is always valid; a positive id must
// reference an existing group so API writes can never create an orphaned
// assignment. Negative ids are rejected.
func validateGroupID(ctx context.Context, tx *sql.Tx, groupID int64) error {
	if groupID < 0 {
		return fmt.Errorf("%w: group_id must not be negative", ErrValidation)
	}
	if groupID == 0 {
		return nil
	}
	var found int
	err := tx.QueryRowContext(ctx, "SELECT 1 FROM groups WHERE id=?", groupID).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: group_id %d does not exist", ErrValidation, groupID)
	}
	if err != nil {
		return fmt.Errorf("validate group id: %w", err)
	}
	return nil
}

func (s *Store) encryptSecret(aad []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	blob, err := s.codec.Encrypt(plaintext, aad)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func (s *Store) decryptSecret(aad []byte, blob []byte) ([]byte, error) {
	if blob == nil {
		return nil, nil
	}
	plaintext, err := s.codec.Decrypt(blob, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// CreateSSH inserts a new SSH profile. The row id is allocated before secret
// fields are encrypted so AAD can bind each ciphertext to its stable
// `warden/ssh/<id>/<field>` location.
func (s *Store) CreateSSH(ctx context.Context, p model.SSHProfile) (model.SSHProfile, error) {
	if err := validateJumpIDs(p.JumpConnectionIDs); err != nil {
		return model.SSHProfile{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := validateSSHMetadata(p); err != nil {
		return model.SSHProfile{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.SSHProfile{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := validateGroupID(ctx, tx, p.GroupID); err != nil {
		return model.SSHProfile{}, err
	}

	ts := nowUTC()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO ssh_connections
			(name, host, port, username, proxy_host, proxy_port, proxy_username,
			 jump_connection_ids, default_dir, group_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Host, p.Port, p.Username, p.ProxyHost, p.ProxyPort, p.ProxyUsername,
		p.JumpConnectionIDs, p.DefaultDir, p.GroupID, ts, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.SSHProfile{}, ErrDuplicate
		}
		return model.SSHProfile{}, fmt.Errorf("insert ssh_connection: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.SSHProfile{}, fmt.Errorf("last insert id: %w", err)
	}

	password, err := s.encryptSecret(sshAAD(id, "password"), p.Password)
	if err != nil {
		return model.SSHProfile{}, err
	}
	proxyPassword, err := s.encryptSecret(sshAAD(id, "proxy_password"), p.ProxyPassword)
	if err != nil {
		return model.SSHProfile{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE ssh_connections
		SET password=?, proxy_password=?
		WHERE id=?`,
		password, proxyPassword, id); err != nil {
		return model.SSHProfile{}, fmt.Errorf("store secrets: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return model.SSHProfile{}, fmt.Errorf("commit: %w", err)
	}

	p.ID = id
	if p.CreatedAt, err = parseTime(ts); err != nil {
		return model.SSHProfile{}, err
	}
	p.UpdatedAt = p.CreatedAt
	return p, nil
}

func (s *Store) GetSSH(ctx context.Context, id int64) (model.SSHProfile, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.name, s.host, s.port, s.username, s.password,
		       s.proxy_host, s.proxy_port, s.proxy_username,
		       s.proxy_password, s.jump_connection_ids, s.default_dir,
		       s.group_id, COALESCE(g.name, ''), s.created_at, s.updated_at
		FROM ssh_connections s
		LEFT JOIN groups g ON g.id = s.group_id
		WHERE s.id = ?`, id)

	var p model.SSHProfile
	var password, proxyPassword []byte
	var createdAt, updatedAt string
	err := row.Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.Username,
		&password, &p.ProxyHost, &p.ProxyPort, &p.ProxyUsername,
		&proxyPassword, &p.JumpConnectionIDs, &p.DefaultDir,
		&p.GroupID, &p.GroupName, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SSHProfile{}, ErrNotFound
	}
	if err != nil {
		return model.SSHProfile{}, fmt.Errorf("scan ssh_connection: %w", err)
	}

	if p.Password, err = s.decryptSecret(sshAAD(id, "password"), password); err != nil {
		return model.SSHProfile{}, fmt.Errorf("decrypt password for %d: %w", id, err)
	}
	if p.ProxyPassword, err = s.decryptSecret(sshAAD(id, "proxy_password"), proxyPassword); err != nil {
		return model.SSHProfile{}, fmt.Errorf("decrypt proxy password for %d: %w", id, err)
	}

	p.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.SSHProfile{}, fmt.Errorf("parse created_at: %w", err)
	}
	p.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.SSHProfile{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return p, nil
}

func (s *Store) ListSSH(ctx context.Context) ([]model.SSHProfile, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM ssh_connections ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list ssh_connections: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan ssh id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	profiles := make([]model.SSHProfile, 0, len(ids))
	for _, id := range ids {
		p, err := s.GetSSH(ctx, id)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// UpdateSSH replaces metadata and jump ids. Secret fields are updated only
// when non-nil; nil keeps the stored value.
func (s *Store) UpdateSSH(ctx context.Context, p model.SSHProfile) error {
	if p.ID == 0 {
		return errors.New("update ssh_connection requires id")
	}
	if err := validateJumpIDs(p.JumpConnectionIDs); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := validateSSHMetadata(p); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := validateGroupID(ctx, tx, p.GroupID); err != nil {
		return err
	}

	ts := nowUTC()
	res, err := tx.ExecContext(ctx, `
		UPDATE ssh_connections
		SET name=?, host=?, port=?, username=?, proxy_host=?, proxy_port=?,
		    proxy_username=?, jump_connection_ids=?, default_dir=?, group_id=?, updated_at=?
		WHERE id=?`,
		p.Name, p.Host, p.Port, p.Username, p.ProxyHost, p.ProxyPort, p.ProxyUsername,
		p.JumpConnectionIDs, p.DefaultDir, p.GroupID, ts, p.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("update ssh_connection: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}

	updates := []struct {
		field     string
		plaintext []byte
	}{
		{"password", p.Password},
		{"proxy_password", p.ProxyPassword},
	}
	for _, u := range updates {
		if u.plaintext == nil {
			continue
		}
		blob, err := s.encryptSecret(sshAAD(p.ID, u.field), u.plaintext)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE ssh_connections SET "+u.field+"=? WHERE id=?", blob, p.ID); err != nil {
			return fmt.Errorf("update %s: %w", u.field, err)
		}
	}

	return tx.Commit()
}

func (s *Store) DeleteSSH(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM ssh_connections WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("delete ssh_connection: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SSHDependents returns SSH profiles whose jump route references id and DB
// profiles whose ssh_connection_id equals id. It never rejects deletion;
// stored dependent JSON is left unchanged.
func (s *Store) SSHDependents(ctx context.Context, id int64) (model.SSHDependents, error) {
	var deps model.SSHDependents

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, jump_connection_ids FROM ssh_connections WHERE id != ?`, id)
	if err != nil {
		return deps, fmt.Errorf("query ssh dependents: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rid int64
		var name, jumpIDs string
		if err := rows.Scan(&rid, &name, &jumpIDs); err != nil {
			return deps, fmt.Errorf("scan ssh dependent: %w", err)
		}
		ids, err := parseJumpIDs(jumpIDs)
		if err != nil {
			continue // tolerate externally corrupted JSON; it carries no reference we can trust
		}
		for _, ref := range ids {
			if ref == id {
				deps.SSH = append(deps.SSH, model.DependentRef{ID: rid, Name: name})
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return deps, err
	}

	dbRows, err := s.db.QueryContext(ctx, `
		SELECT id, name FROM db_connections WHERE ssh_connection_id = ?`, id)
	if err != nil {
		return deps, fmt.Errorf("query db dependents: %w", err)
	}
	defer dbRows.Close()
	for dbRows.Next() {
		var rid int64
		var name string
		if err := dbRows.Scan(&rid, &name); err != nil {
			return deps, fmt.Errorf("scan db dependent: %w", err)
		}
		deps.DB = append(deps.DB, model.DependentRef{ID: rid, Name: name})
	}
	if err := dbRows.Err(); err != nil {
		return deps, err
	}

	return deps, nil
}

func (s *Store) CreateDB(ctx context.Context, p model.DBProfile) (model.DBProfile, error) {
	if err := validateDBMetadata(p); err != nil {
		return model.DBProfile{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DBProfile{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := validateGroupID(ctx, tx, p.GroupID); err != nil {
		return model.DBProfile{}, err
	}

	ts := nowUTC()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO db_connections
			(name, host, port, username, database, ssh_connection_id, group_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Host, p.Port, p.Username, p.Database, p.SSHConnectionID, p.GroupID, ts, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.DBProfile{}, ErrDuplicate
		}
		return model.DBProfile{}, fmt.Errorf("insert db_connection: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.DBProfile{}, fmt.Errorf("last insert id: %w", err)
	}

	password, err := s.encryptSecret(dbAAD(id, "password"), p.Password)
	if err != nil {
		return model.DBProfile{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE db_connections SET password=? WHERE id=?",
		password, id); err != nil {
		return model.DBProfile{}, fmt.Errorf("store password: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return model.DBProfile{}, fmt.Errorf("commit: %w", err)
	}

	p.ID = id
	if p.CreatedAt, err = parseTime(ts); err != nil {
		return model.DBProfile{}, err
	}
	p.UpdatedAt = p.CreatedAt
	return p, nil
}

func (s *Store) GetDB(ctx context.Context, id int64) (model.DBProfile, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT d.id, d.name, d.host, d.port, d.username, d.password, d.database, d.ssh_connection_id,
		       d.group_id, COALESCE(g.name, ''), d.created_at, d.updated_at
		FROM db_connections d
		LEFT JOIN groups g ON g.id = d.group_id
		WHERE d.id = ?`, id)

	var p model.DBProfile
	var password []byte
	var createdAt, updatedAt string
	err := row.Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.Username, &password,
		&p.Database, &p.SSHConnectionID, &p.GroupID, &p.GroupName, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.DBProfile{}, ErrNotFound
	}
	if err != nil {
		return model.DBProfile{}, fmt.Errorf("scan db_connection: %w", err)
	}

	if p.Password, err = s.decryptSecret(dbAAD(id, "password"), password); err != nil {
		return model.DBProfile{}, fmt.Errorf("decrypt password for %d: %w", id, err)
	}
	if p.CreatedAt, err = parseTime(createdAt); err != nil {
		return model.DBProfile{}, fmt.Errorf("parse created_at: %w", err)
	}
	if p.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return model.DBProfile{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return p, nil
}

func (s *Store) ListDB(ctx context.Context) ([]model.DBProfile, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM db_connections ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list db_connections: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan db id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	profiles := make([]model.DBProfile, 0, len(ids))
	for _, id := range ids {
		p, err := s.GetDB(ctx, id)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// UpdateDB replaces metadata. The password is updated only when non-nil.
func (s *Store) UpdateDB(ctx context.Context, p model.DBProfile) error {
	if p.ID == 0 {
		return errors.New("update db_connection requires id")
	}
	if err := validateDBMetadata(p); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := validateGroupID(ctx, tx, p.GroupID); err != nil {
		return err
	}

	ts := nowUTC()
	res, err := tx.ExecContext(ctx, `
		UPDATE db_connections
		SET name=?, host=?, port=?, username=?, database=?, ssh_connection_id=?, group_id=?, updated_at=?
		WHERE id=?`,
		p.Name, p.Host, p.Port, p.Username, p.Database, p.SSHConnectionID, p.GroupID, ts, p.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("update db_connection: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}

	if p.Password != nil {
		blob, err := s.encryptSecret(dbAAD(p.ID, "password"), p.Password)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE db_connections SET password=? WHERE id=?",
			blob, p.ID); err != nil {
			return fmt.Errorf("update password: %w", err)
		}
	}

	return tx.Commit()
}

func (s *Store) DeleteDB(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM db_connections WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("delete db_connection: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

func sshAAD(id int64, field string) []byte {
	return []byte(fmt.Sprintf("warden/ssh/%d/%s", id, field))
}

func dbAAD(id int64, field string) []byte {
	return []byte(fmt.Sprintf("warden/db/%d/%s", id, field))
}

func validateSSHMetadata(p model.SSHProfile) error {
	if !connectionNameRe.MatchString(p.Name) {
		return fmt.Errorf("invalid ssh connection name %q: must match [A-Za-z0-9._-]{1,100}", p.Name)
	}
	if strings.TrimSpace(p.Host) == "" {
		return errors.New("ssh host must not be empty")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("ssh port %d out of range 1-65535", p.Port)
	}
	if strings.TrimSpace(p.Username) == "" {
		return errors.New("ssh username must not be empty")
	}
	if p.ProxyHost != "" && (p.ProxyPort < 1 || p.ProxyPort > 65535) {
		return fmt.Errorf("proxy port %d out of range 1-65535", p.ProxyPort)
	}
	if err := validateDefaultDir(p.DefaultDir); err != nil {
		return err
	}
	return nil
}

// validateDefaultDir enforces an optional absolute remote working
// directory. Empty is allowed (no cd prefix). Non-empty must be an
// absolute path with no path-traversal segments, no control characters
// or NUL bytes, and at most maxDefaultDirBytes (4 KiB).
func validateDefaultDir(dir string) error {
	if dir == "" {
		return nil
	}
	const maxDefaultDirBytes = 4096
	if len(dir) > maxDefaultDirBytes {
		return fmt.Errorf("default_dir exceeds %d bytes", maxDefaultDirBytes)
	}
	if !strings.HasPrefix(dir, "/") {
		return errors.New("default_dir must be an absolute path starting with '/'")
	}
	for _, r := range dir {
		if r == 0 || r < 0x20 || r == 0x7f {
			return errors.New("default_dir must not contain control characters or NUL")
		}
	}
	for _, seg := range strings.Split(dir, "/") {
		if seg == ".." {
			return errors.New("default_dir must not contain '..' segments")
		}
	}
	return nil
}

func validateDBMetadata(p model.DBProfile) error {
	if !connectionNameRe.MatchString(p.Name) {
		return fmt.Errorf("invalid db connection name %q: must match [A-Za-z0-9._-]{1,100}", p.Name)
	}
	if strings.TrimSpace(p.Host) == "" {
		return errors.New("db host must not be empty")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("db port %d out of range 1-65535", p.Port)
	}
	if strings.TrimSpace(p.Username) == "" {
		return errors.New("db username must not be empty")
	}
	if p.SSHConnectionID < 0 {
		return fmt.Errorf("db ssh_connection_id %d must not be negative", p.SSHConnectionID)
	}
	return nil
}

func parseTime(value string) (t time.Time, err error) {
	return time.Parse(timeLayout, value)
}
