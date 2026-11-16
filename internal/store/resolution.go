package store

import (
	"context"
	"database/sql"
	"errors"

	"warden/internal/model"
)

// ResolutionSnapshot retains one SQLite read transaction across structural
// validation and secret loading. Concurrent profile/archive/key updates become
// visible only to later resolutions. Metadata reads select no ciphertext; the
// same transaction supplies secret fields after the complete graph is valid.
// The caller must Close on every exit. The runtime's response vault lease is
// independent and must still span resolution and response delivery.
type ResolutionSnapshot struct {
	store *Store
	tx    *sql.Tx
}

func (s *Store) BeginResolution(ctx context.Context) (*ResolutionSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	return &ResolutionSnapshot{store: s, tx: tx}, nil
}

// Close releases the read snapshot without committing any changes. This seam
// exposes no writes (the SQLite driver uses a deferred BEGIN for ReadOnly).
func (s *ResolutionSnapshot) Close() { _ = s.tx.Rollback() }
func (s *ResolutionSnapshot) GetSSHMetadata(ctx context.Context, id int64) (model.SSHProfile, error) {
	return s.store.getSSH(ctx, s.tx, id, false)
}
func (s *ResolutionSnapshot) GetDBMetadata(ctx context.Context, id int64) (model.DBProfile, error) {
	return s.store.getDB(ctx, s.tx, id, false)
}
func (s *ResolutionSnapshot) GetSSH(ctx context.Context, id int64) (model.SSHProfile, error) {
	return s.store.getSSH(ctx, s.tx, id, true)
}
func (s *ResolutionSnapshot) GetDB(ctx context.Context, id int64) (model.DBProfile, error) {
	return s.store.getDB(ctx, s.tx, id, true)
}
func (s *ResolutionSnapshot) GetKeyPair(ctx context.Context, id int64) (model.KeyPair, error) {
	return s.store.getKeyPair(ctx, s.tx, id)
}

// HasPrivateKey checks the existing SQL-NULL presence contract without loading
// or decrypting key material. Deleted and cleared pairs are structural errors.
func (s *ResolutionSnapshot) HasPrivateKey(ctx context.Context, id int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var has bool
	err := s.tx.QueryRowContext(ctx, "SELECT private_key IS NOT NULL FROM key_pairs WHERE id=?", id).Scan(&has)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	return has, err
}
