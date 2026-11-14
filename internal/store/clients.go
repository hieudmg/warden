package store

import (
	"context"
	"database/sql"
	"errors"
)

// ClientCredential contains only a hash commitment, never a recoverable token.
type ClientCredential struct {
	ID         string `json:"id"`
	Verifier   string `json:"fingerprint"`
	Label      string `json:"label"`
	Generation uint64 `json:"generation"`
	Created    int64  `json:"created"`
	Revoked    bool   `json:"revoked"`
}

// ApproveClient couples registration to the exact current complete identity.
// The no-op CAS obtains SQLite's writer lock before the insert, excluding a
// concurrent recovery-generation change. No wrappers/counters are rewritten.
func (s *Store) ApproveClient(ctx context.Context, identity []byte, c ClientCredential) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE installation SET identity=identity WHERE singleton=1 AND identity=?`, identity)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	// Prune revoked records; active credentials are explicitly bounded.
	if _, err = tx.ExecContext(ctx, `DELETE FROM client_credentials WHERE revoked=1 OR generation<>?`, c.Generation); err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO client_credentials(id,verifier,label,generation,created) SELECT ?,?,?,?,? WHERE (SELECT count(*) FROM client_credentials)<128`, c.ID, c.Verifier, c.Label, c.Generation, c.Created)
	if err != nil {
		return err
	}
	n, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrValidation
	}
	return tx.Commit()
}
func (s *Store) ClientByVerifier(ctx context.Context, verifier string) (ClientCredential, error) {
	var c ClientCredential
	err := s.db.QueryRowContext(ctx, `SELECT id,verifier,label,generation,created,revoked FROM client_credentials WHERE verifier=?`, verifier).Scan(&c.ID, &c.Verifier, &c.Label, &c.Generation, &c.Created, &c.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return c, err
}
func (s *Store) Clients(ctx context.Context) ([]ClientCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,verifier,label,generation,created,revoked FROM client_credentials ORDER BY created,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientCredential{}
	for rows.Next() {
		var c ClientCredential
		if err = rows.Scan(&c.ID, &c.Verifier, &c.Label, &c.Generation, &c.Created, &c.Revoked); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) RevokeClient(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE client_credentials SET revoked=1 WHERE id=?`, id)
	return err
}
