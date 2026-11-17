package store

import (
	"context"
	"database/sql"
	"fmt"

	"warden/internal/model"
)

func (s *Store) exportHTTPConnections(ctx context.Context, tx *sql.Tx) ([]model.TransferHTTPConnection, error) {
	rows, err := tx.QueryContext(ctx, httpSelect+" ORDER BY h.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.TransferHTTPConnection, 0)
	for rows.Next() {
		p, err := s.scanHTTP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, model.TransferHTTPConnection{
			ID: p.ID, Name: p.Name, Origin: p.Origin, AuthType: p.AuthType,
			Credential: string(p.Credential), Username: string(p.Username), Password: string(p.Password),
			GroupID: p.GroupID, Archived: p.Archived,
			CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		})
	}
	return out, rows.Err()
}

func validateHTTPTransfer(connections []model.TransferHTTPConnection) error {
	ids := make(map[int64]struct{})
	names := make(map[string]bool)
	for _, c := range connections {
		if err := claimTransferID("HTTP connection", c.ID, ids); err != nil {
			return err
		}
		if names[c.Name] {
			return fmt.Errorf("%w: duplicate HTTP connection name", ErrValidation)
		}
		names[c.Name] = true
		if err := validateHTTPProfile(model.HTTPProfile{Name: c.Name, Origin: c.Origin, AuthType: c.AuthType, Credential: []byte(c.Credential), Username: []byte(c.Username), Password: []byte(c.Password), GroupID: c.GroupID}); err != nil {
			return fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if err := validateTransferTimestamps("HTTP connection", c.CreatedAt, c.UpdatedAt); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) insertHTTPConnections(ctx context.Context, tx *sql.Tx, connections []model.TransferHTTPConnection) error {
	for _, c := range connections {
		if _, err := tx.ExecContext(ctx, "INSERT INTO http_connections (id,name,origin,auth_type,group_id,archived,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)", c.ID, c.Name, c.Origin, c.AuthType, c.GroupID, c.Archived, formatTransferTime(c.CreatedAt), formatTransferTime(c.UpdatedAt)); err != nil {
			return err
		}
		if err := s.writeHTTPSecrets(ctx, tx, model.HTTPProfile{ID: c.ID, Credential: []byte(c.Credential), Username: []byte(c.Username), Password: []byte(c.Password)}); err != nil {
			return err
		}
	}
	return nil
}
