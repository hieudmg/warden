package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"warden/internal/model"
)

var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// normalizeGroupName trims surrounding whitespace and validates the result.
// Only the trimmed value is ever persisted, so " prod " and "prod" cannot
// become distinct groups.
func normalizeGroupName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !groupNameRe.MatchString(name) {
		return "", fmt.Errorf("%w: invalid group name %q: must match [A-Za-z0-9._-]{1,100}", ErrValidation, name)
	}
	return name, nil
}

// groupCountsSQL is the shared count subquery pair used by every group read:
// one aggregate query per table, never a three-way join, so counts cannot
// multiply each other.
const groupCountsSQL = `
       (SELECT COUNT(*) FROM ssh_connections ssh WHERE ssh.group_id = g.id),
       (SELECT COUNT(*) FROM db_connections d WHERE d.group_id = g.id)`

// CreateGroup inserts a new group with a trimmed, validated name. The
// returned group carries its id, timestamps, and zero connection counts.
func (s *Store) CreateGroup(ctx context.Context, g model.Group) (model.Group, error) {
	name, err := normalizeGroupName(g.Name)
	if err != nil {
		return model.Group{}, err
	}

	ts := nowUTC()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO groups (name, created_at, updated_at)
		VALUES (?, ?, ?)`, name, ts, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.Group{}, ErrDuplicate
		}
		return model.Group{}, fmt.Errorf("insert group: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.Group{}, fmt.Errorf("last insert id: %w", err)
	}

	createdAt, err := parseTime(ts)
	if err != nil {
		return model.Group{}, fmt.Errorf("parse created_at: %w", err)
	}
	return model.Group{
		ID:        id,
		Name:      name,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
	}, nil
}

// GetGroup returns one group by id, including its connection counts.
func (s *Store) GetGroup(ctx context.Context, id int64) (model.Group, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT g.id, g.name, `+groupCountsSQL+`,
		       g.created_at, g.updated_at
		FROM groups g WHERE g.id = ?`, id)

	var g model.Group
	var createdAt, updatedAt string
	err := row.Scan(&g.ID, &g.Name, &g.SSHConnectionCount, &g.DBConnectionCount,
		&createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Group{}, ErrNotFound
	}
	if err != nil {
		return model.Group{}, fmt.Errorf("scan group: %w", err)
	}
	if g.CreatedAt, err = parseTime(createdAt); err != nil {
		return model.Group{}, fmt.Errorf("parse created_at: %w", err)
	}
	if g.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return model.Group{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return g, nil
}

// ListGroups returns all groups ordered by name, each with its SSH and DB
// connection counts.
func (s *Store) ListGroups(ctx context.Context) ([]model.Group, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.id, g.name, `+groupCountsSQL+`,
		       g.created_at, g.updated_at
		FROM groups g
		ORDER BY g.name`)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var groups []model.Group
	for rows.Next() {
		var g model.Group
		var createdAt, updatedAt string
		if err := rows.Scan(&g.ID, &g.Name, &g.SSHConnectionCount, &g.DBConnectionCount,
			&createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		if g.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("parse group created_at: %w", err)
		}
		if g.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, fmt.Errorf("parse group updated_at: %w", err)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}

// UpdateGroup renames a group. The id is required; the name is trimmed and
// validated, and updated_at is bumped to the current time.
func (s *Store) UpdateGroup(ctx context.Context, g model.Group) error {
	if g.ID == 0 {
		return errors.New("update group requires id")
	}
	name, err := normalizeGroupName(g.Name)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE groups SET name=?, updated_at=? WHERE id=?`, name, nowUTC(), g.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("update group: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteGroup deletes a group after clearing every SSH/DB reference to it.
// The clears and the delete are one transaction, so deletion is never
// blocked by profiles referencing the group and no profile ever retains a
// deleted group's id.
func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		"UPDATE ssh_connections SET group_id=0 WHERE group_id=?", id); err != nil {
		return fmt.Errorf("clear ssh group references: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE db_connections SET group_id=0 WHERE group_id=?", id); err != nil {
		return fmt.Errorf("clear db group references: %w", err)
	}

	res, err := tx.ExecContext(ctx, "DELETE FROM groups WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// GroupDependents lists profiles referencing a group id. A missing group
// returns ErrNotFound; a found group returns possibly-empty reference
// slices.
func (s *Store) GroupDependents(ctx context.Context, id int64) (model.GroupDependents, error) {
	if _, err := s.GetGroup(ctx, id); err != nil {
		return model.GroupDependents{}, err
	}

	var deps model.GroupDependents

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name FROM ssh_connections WHERE group_id = ?`, id)
	if err != nil {
		return deps, fmt.Errorf("query ssh group dependents: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rid int64
		var name string
		if err := rows.Scan(&rid, &name); err != nil {
			return deps, fmt.Errorf("scan ssh group dependent: %w", err)
		}
		deps.SSH = append(deps.SSH, model.DependentRef{ID: rid, Name: name})
	}
	if err := rows.Err(); err != nil {
		return deps, err
	}

	dbRows, err := s.db.QueryContext(ctx, `
		SELECT id, name FROM db_connections WHERE group_id = ?`, id)
	if err != nil {
		return deps, fmt.Errorf("query db group dependents: %w", err)
	}
	defer dbRows.Close()
	for dbRows.Next() {
		var rid int64
		var name string
		if err := dbRows.Scan(&rid, &name); err != nil {
			return deps, fmt.Errorf("scan db group dependent: %w", err)
		}
		deps.DB = append(deps.DB, model.DependentRef{ID: rid, Name: name})
	}
	if err := dbRows.Err(); err != nil {
		return deps, err
	}

	return deps, nil
}
