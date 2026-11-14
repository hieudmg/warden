package store

import "context"

// CompareAndSwapInstallation publishes complete validated identity and revokes
// sessions in one transaction. Recovery also advances AuthorizationGeneration
// in the identity: T4 verifiers MUST bind/check that generation on every request.
// Client-verifier rows are not rebound: the generation change invalidates them.
func (s *Store) CompareAndSwapInstallation(ctx context.Context, before, after []byte, revoked string, all bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE installation SET identity=? WHERE singleton=1 AND format=1 AND identity=?`, after, before)
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
	if all {
		_, err = tx.ExecContext(ctx, `DELETE FROM web_sessions`)
	} else if revoked != "" {
		_, err = tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE credential_id=?`, revoked)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
