package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"warden/internal/model"
)

// keyPairAAD binds a key-pair ciphertext to its stable
// `warden/key-pair/<id>/<field>` location so blobs cannot be swapped
// between fields or rows.
func keyPairAAD(id int64, field string) []byte {
	return []byte(fmt.Sprintf("warden/key-pair/%d/%s", id, field))
}

// CreateKeyPair inserts a new key pair. The row id is allocated before
// secret fields are encrypted so AAD can bind each ciphertext to its stable
// `warden/key-pair/<id>/<field>` location. Empty fields store SQL NULL.
func (s *Store) CreateKeyPair(ctx context.Context, p model.KeyPair) (model.KeyPair, error) {
	name, err := normalizeGroupName(p.Name)
	if err != nil {
		return model.KeyPair{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.KeyPair{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ts := nowUTC()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO key_pairs (name, created_at, updated_at)
		VALUES (?, ?, ?)`, name, ts, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.KeyPair{}, ErrDuplicate
		}
		return model.KeyPair{}, fmt.Errorf("insert key_pair: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.KeyPair{}, fmt.Errorf("last insert id: %w", err)
	}

	publicKey, err := s.encryptSecret(keyPairAAD(id, "public_key"), p.PublicKey)
	if err != nil {
		return model.KeyPair{}, err
	}
	privateKey, err := s.encryptSecret(keyPairAAD(id, "private_key"), p.PrivateKey)
	if err != nil {
		return model.KeyPair{}, err
	}
	passphrase, err := s.encryptSecret(keyPairAAD(id, "private_key_passphrase"), p.PrivateKeyPassphrase)
	if err != nil {
		return model.KeyPair{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE key_pairs
		SET public_key=?, private_key=?, private_key_passphrase=?
		WHERE id=?`,
		publicKey, privateKey, passphrase, id); err != nil {
		return model.KeyPair{}, fmt.Errorf("store secrets: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return model.KeyPair{}, fmt.Errorf("commit: %w", err)
	}

	p.ID = id
	p.Name = name
	if p.CreatedAt, err = parseTime(ts); err != nil {
		return model.KeyPair{}, err
	}
	p.UpdatedAt = p.CreatedAt
	return p, nil
}

// GetKeyPair returns a key pair with every stored field decrypted.
func (s *Store) GetKeyPair(ctx context.Context, id int64) (model.KeyPair, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, public_key, private_key, private_key_passphrase,
		       created_at, updated_at
		FROM key_pairs WHERE id = ?`, id)

	var p model.KeyPair
	var publicKey, privateKey, passphrase []byte
	var createdAt, updatedAt string
	err := row.Scan(&p.ID, &p.Name, &publicKey, &privateKey, &passphrase,
		&createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.KeyPair{}, ErrNotFound
	}
	if err != nil {
		return model.KeyPair{}, fmt.Errorf("scan key_pair: %w", err)
	}

	if p.PublicKey, err = s.decryptSecret(keyPairAAD(id, "public_key"), publicKey); err != nil {
		return model.KeyPair{}, fmt.Errorf("decrypt public key for %d: %w", id, err)
	}
	if p.PrivateKey, err = s.decryptSecret(keyPairAAD(id, "private_key"), privateKey); err != nil {
		return model.KeyPair{}, fmt.Errorf("decrypt private key for %d: %w", id, err)
	}
	if p.PrivateKeyPassphrase, err = s.decryptSecret(keyPairAAD(id, "private_key_passphrase"), passphrase); err != nil {
		return model.KeyPair{}, fmt.Errorf("decrypt passphrase for %d: %w", id, err)
	}

	if p.CreatedAt, err = parseTime(createdAt); err != nil {
		return model.KeyPair{}, fmt.Errorf("parse created_at: %w", err)
	}
	if p.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return model.KeyPair{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return p, nil
}

// ListKeyPairs returns metadata and presence flags only. It never decrypts
// key material, so list payloads cannot leak raw values.
func (s *Store) ListKeyPairs(ctx context.Context) ([]model.KeyPairSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name,
		       public_key IS NOT NULL,
		       private_key IS NOT NULL,
		       private_key_passphrase IS NOT NULL,
		       created_at, updated_at
		FROM key_pairs ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list key_pairs: %w", err)
	}
	defer rows.Close()

	all := make([]model.KeyPairSummary, 0)
	for rows.Next() {
		var p model.KeyPairSummary
		var createdAt, updatedAt string
		if err := rows.Scan(&p.ID, &p.Name,
			&p.HasPublicKey, &p.HasPrivateKey, &p.HasPrivateKeyPassphrase,
			&createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan key_pair summary: %w", err)
		}
		if p.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, err
		}
		if p.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, err
		}
		all = append(all, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return all, nil
}

// UpdateKeyPair replaces metadata and bumps updated_at. Secret fields are
// updated only when non-nil; nil keeps the stored value and a non-nil empty
// value writes SQL NULL (explicit clear).
func (s *Store) UpdateKeyPair(ctx context.Context, p model.KeyPair) error {
	if p.ID == 0 {
		return errors.New("update key_pair requires id")
	}
	name, err := normalizeGroupName(p.Name)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ts := nowUTC()
	res, err := tx.ExecContext(ctx, `
		UPDATE key_pairs SET name=?, updated_at=? WHERE id=?`,
		name, ts, p.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("update key_pair: %w", err)
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
		{"public_key", p.PublicKey},
		{"private_key", p.PrivateKey},
		{"private_key_passphrase", p.PrivateKeyPassphrase},
	}
	for _, u := range updates {
		if u.plaintext == nil {
			continue
		}
		blob, err := s.encryptSecret(keyPairAAD(p.ID, u.field), u.plaintext)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE key_pairs SET "+u.field+"=? WHERE id=?", blob, p.ID); err != nil {
			return fmt.Errorf("update %s: %w", u.field, err)
		}
	}

	return tx.Commit()
}

// DeleteKeyPair deletes only the key-pair row. SSH rows referencing it are
// left unchanged; references remain dangling for explicit resolution
// failure.
func (s *Store) DeleteKeyPair(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM key_pairs WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("delete key_pair: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// KeyPairDependents lists SSH connections referencing a key pair id. A
// missing pair returns ErrNotFound; a found pair returns possibly-empty
// references for deletion warnings.
func (s *Store) KeyPairDependents(ctx context.Context, id int64) ([]model.DependentRef, error) {
	if _, err := s.GetKeyPair(ctx, id); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name FROM ssh_connections WHERE key_pair_id = ? ORDER BY name`, id)
	if err != nil {
		return nil, fmt.Errorf("query key-pair dependents: %w", err)
	}
	defer rows.Close()

	var deps []model.DependentRef
	for rows.Next() {
		var rid int64
		var name string
		if err := rows.Scan(&rid, &name); err != nil {
			return nil, fmt.Errorf("scan key-pair dependent: %w", err)
		}
		deps = append(deps, model.DependentRef{ID: rid, Name: name})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return deps, nil
}
