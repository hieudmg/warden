package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"warden/internal/model"
)

func httpAAD(id int64, field string) []byte {
	return []byte(fmt.Sprintf("warden/http/%d/%s", id, field))
}

func validateHTTPProfile(p model.HTTPProfile) error {
	if !connectionNameRe.MatchString(p.Name) {
		return errors.New("invalid HTTP connection name: must match [A-Za-z0-9._-]{1,100}")
	}
	if err := model.ValidateHTTPOrigin(p.Origin); err != nil {
		return err
	}
	if err := validateConnectionNote(p.Note); err != nil {
		return err
	}
	if p.GroupID < 0 {
		return errors.New("group_id must not be negative")
	}
	switch p.AuthType {
	case "bearer", "x_api_key":
		if len(p.Username) > 0 || len(p.Password) > 0 {
			return errors.New("username/password require basic auth")
		}
	case "basic":
		if len(p.Credential) > 0 {
			return errors.New("credential requires bearer or x_api_key auth")
		}
		if strings.Contains(string(p.Username), ":") {
			return errors.New("basic username must not contain colon")
		}
	default:
		return errors.New("auth_type must be bearer, x_api_key or basic")
	}
	for _, secret := range [][]byte{p.Credential, p.Username, p.Password} {
		if len(secret) > 8192 {
			return errors.New("HTTP credential field exceeds 8192 bytes")
		}
		for _, b := range secret {
			if b < 0x20 || b == 0x7f {
				return errors.New("HTTP credentials must not contain control characters")
			}
		}
	}
	return nil
}

func (s *Store) CreateHTTP(ctx context.Context, p model.HTTPProfile) (model.HTTPProfile, error) {
	if err := validateHTTPProfile(p); err != nil {
		return model.HTTPProfile{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.HTTPProfile{}, err
	}
	defer tx.Rollback()
	if err := validateGroupID(ctx, tx, p.GroupID); err != nil {
		return model.HTTPProfile{}, err
	}
	ts := nowUTC()
	res, err := tx.ExecContext(ctx, "INSERT INTO http_connections (name,origin,auth_type,group_id,created_at,updated_at) VALUES (?,?,?,?,?,?)", p.Name, p.Origin, p.AuthType, p.GroupID, ts, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.HTTPProfile{}, ErrDuplicate
		}
		return model.HTTPProfile{}, err
	}
	p.ID, err = res.LastInsertId()
	if err != nil {
		return model.HTTPProfile{}, err
	}
	if err := s.writeHTTPSecrets(ctx, tx, p); err != nil {
		return model.HTTPProfile{}, err
	}
	if err := setConnectionNote(ctx, tx, "http", p.ID, p.Note); err != nil {
		return model.HTTPProfile{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.HTTPProfile{}, err
	}
	return s.GetHTTP(ctx, p.ID)
}

func (s *Store) writeHTTPSecrets(ctx context.Context, tx *sql.Tx, p model.HTTPProfile) error {
	for _, field := range []struct {
		name  string
		value []byte
	}{{"credential", p.Credential}, {"username", p.Username}, {"password", p.Password}} {
		if field.value == nil {
			continue
		}
		blob, err := s.encryptSecret(httpAAD(p.ID, field.name), field.value)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE http_connections SET "+field.name+"=? WHERE id=?", blob, p.ID); err != nil {
			return err
		}
	}
	return nil
}

const httpSelect = `SELECT h.id,h.name,h.origin,h.auth_type,h.credential,h.username,h.password,h.group_id,COALESCE(g.name,''),COALESCE(n.note,''),h.archived,h.created_at,h.updated_at
 FROM http_connections h LEFT JOIN groups g ON g.id=h.group_id
 LEFT JOIN connection_notes n ON n.connection_type='http' AND n.connection_id=h.id`

type httpScanner interface{ Scan(...any) error }

func (s *Store) scanHTTP(row httpScanner) (model.HTTPProfile, error) {
	var p model.HTTPProfile
	var credential, username, password []byte
	var created, updated string
	err := row.Scan(&p.ID, &p.Name, &p.Origin, &p.AuthType, &credential, &username, &password, &p.GroupID, &p.GroupName, &p.Note, &p.Archived, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	if p.Credential, err = s.decryptSecret(httpAAD(p.ID, "credential"), credential); err != nil {
		return p, err
	}
	if p.Username, err = s.decryptSecret(httpAAD(p.ID, "username"), username); err != nil {
		return p, err
	}
	if p.Password, err = s.decryptSecret(httpAAD(p.ID, "password"), password); err != nil {
		return p, err
	}
	if p.CreatedAt, err = parseTime(created); err != nil {
		return p, err
	}
	p.UpdatedAt, err = parseTime(updated)
	return p, err
}
func (s *Store) GetHTTP(ctx context.Context, id int64) (model.HTTPProfile, error) {
	return s.scanHTTP(s.db.QueryRowContext(ctx, httpSelect+" WHERE h.id=?", id))
}
func (s *Store) ListHTTP(ctx context.Context) ([]model.HTTPProfile, error) {
	rows, err := s.db.QueryContext(ctx, httpSelect+" ORDER BY h.name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.HTTPProfile, 0)
	for rows.Next() {
		p, err := s.scanHTTP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) UpdateHTTP(ctx context.Context, p model.HTTPProfile) error {
	if err := validateHTTPProfile(p); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateGroupID(ctx, tx, p.GroupID); err != nil {
		return err
	}
	var oldType string
	if err := tx.QueryRowContext(ctx, "SELECT auth_type FROM http_connections WHERE id=?", p.ID).Scan(&oldType); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if oldType != p.AuthType {
		if _, err := tx.ExecContext(ctx, "UPDATE http_connections SET credential=NULL,username=NULL,password=NULL WHERE id=?", p.ID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE http_connections SET name=?,origin=?,auth_type=?,group_id=?,updated_at=? WHERE id=?", p.Name, p.Origin, p.AuthType, p.GroupID, nowUTC(), p.ID); err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return err
	}
	if err := s.writeHTTPSecrets(ctx, tx, p); err != nil {
		return err
	}
	if err := setConnectionNote(ctx, tx, "http", p.ID, p.Note); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteHTTP(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "DELETE FROM http_connections WHERE id=?", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM connection_notes WHERE connection_type='http' AND connection_id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SetHTTPArchived(ctx context.Context, id int64, archived bool) error {
	return setArchived(ctx, s.db, "http_connections", id, archived)
}
