package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"warden/internal/model"
)

func TestGroupCreateStoresTrimmedName(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateGroup(ctx, model.Group{Name: "  prod  "})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if created.ID == 0 {
		t.Error("CreateGroup returned zero id")
	}
	if created.Name != "prod" {
		t.Errorf("CreateGroup name = %q, want trimmed %q", created.Name, "prod")
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("CreateGroup returned zero timestamps")
	}

	got, err := s.GetGroup(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got.Name != "prod" {
		t.Errorf("GetGroup name = %q, want prod", got.Name)
	}
	if got.SSHConnectionCount != 0 || got.DBConnectionCount != 0 {
		t.Errorf("GetGroup counts = %d/%d, want 0/0", got.SSHConnectionCount, got.DBConnectionCount)
	}
}

func TestGroupNameValidationReturnsErrValidation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, name := range []string{
		"",
		"   ",
		"bad name!",
		"prod/x",
		"pro\nd",
		"éclair",
		strings.Repeat("a", 101),
	} {
		if _, err := s.CreateGroup(ctx, model.Group{Name: name}); !errors.Is(err, ErrValidation) {
			t.Errorf("CreateGroup name %q error = %v, want ErrValidation", name, err)
		}
	}
}

func TestGroupDuplicateNameReturnsErrDuplicate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateGroup(ctx, model.Group{Name: "prod"}); err != nil {
		t.Fatalf("first CreateGroup: %v", err)
	}
	if _, err := s.CreateGroup(ctx, model.Group{Name: "prod"}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate CreateGroup error = %v, want ErrDuplicate", err)
	}
	// Trimming makes " prod " collide with the existing "prod".
	if _, err := s.CreateGroup(ctx, model.Group{Name: " prod "}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("trimmed duplicate CreateGroup error = %v, want ErrDuplicate", err)
	}
}

func TestGroupGetNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.GetGroup(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetGroup missing error = %v, want ErrNotFound", err)
	}
}

func TestGroupListOrderedByNameWithZeroCounts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, name := range []string{"zeta", "alpha", "mid"} {
		if _, err := s.CreateGroup(ctx, model.Group{Name: name}); err != nil {
			t.Fatalf("CreateGroup %s: %v", name, err)
		}
	}
	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 3 {
		t.Fatalf("ListGroups returned %d rows, want 3", len(groups))
	}
	wantNames := []string{"alpha", "mid", "zeta"}
	for i, want := range wantNames {
		if groups[i].Name != want {
			t.Errorf("ListGroups[%d].Name = %q, want %q", i, groups[i].Name, want)
		}
		if groups[i].SSHConnectionCount != 0 || groups[i].DBConnectionCount != 0 {
			t.Errorf("ListGroups[%d] counts = %d/%d, want 0/0", i, groups[i].SSHConnectionCount, groups[i].DBConnectionCount)
		}
	}
}

func TestListGroupsIncludesConnectionCounts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	group, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	ssh1, err := s.CreateSSH(ctx, SSHProfileForTest("web-1", "[]"))
	if err != nil {
		t.Fatal(err)
	}
	ssh2, err := s.CreateSSH(ctx, SSHProfileForTest("web-2", "[]"))
	if err != nil {
		t.Fatal(err)
	}
	db1, err := s.CreateDB(ctx, DBProfileForTest("appdb", 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{ssh1.ID, ssh2.ID} {
		if _, err := s.db.ExecContext(ctx, "UPDATE ssh_connections SET group_id=? WHERE id=?", group.ID, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.ExecContext(ctx, "UPDATE db_connections SET group_id=? WHERE id=?", group.ID, db1.ID); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("ListGroups returned %d rows, want 1", len(got))
	}
	if got[0].SSHConnectionCount != 2 || got[0].DBConnectionCount != 1 {
		t.Errorf("counts = %d/%d, want 2/1", got[0].SSHConnectionCount, got[0].DBConnectionCount)
	}
}

func TestGroupUpdateRename(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	group, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	group.Name = "production"
	if err := s.UpdateGroup(ctx, group); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	got, err := s.GetGroup(ctx, group.ID)
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got.Name != "production" {
		t.Errorf("GetGroup name = %q, want production", got.Name)
	}
	if got.UpdatedAt.Before(group.CreatedAt) {
		t.Error("updated_at did not advance after rename")
	}
}

func TestUpdateGroupRequiresIDAndExistingRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpdateGroup(ctx, model.Group{Name: "x"}); err == nil {
		t.Error("UpdateGroup without id accepted")
	}
	if err := s.UpdateGroup(ctx, model.Group{ID: 999999, Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateGroup missing error = %v, want ErrNotFound", err)
	}
}

func TestDeleteGroupClearsProfileAssignments(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	group, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}

	ssh, err := s.CreateSSH(ctx, SSHProfileForTest("web", "[]"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := s.CreateDB(ctx, DBProfileForTest("appdb", 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		"UPDATE ssh_connections SET group_id=? WHERE id=?", group.ID, ssh.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		"UPDATE db_connections SET group_id=? WHERE id=?", group.ID, db.ID); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatal(err)
	}
	var sshGroupID, dbGroupID int64
	if err := s.db.QueryRowContext(ctx, "SELECT group_id FROM ssh_connections WHERE id=?", ssh.ID).Scan(&sshGroupID); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT group_id FROM db_connections WHERE id=?", db.ID).Scan(&dbGroupID); err != nil {
		t.Fatal(err)
	}
	if sshGroupID != 0 || dbGroupID != 0 {
		t.Fatalf("group ids = %d, %d; want 0, 0", sshGroupID, dbGroupID)
	}
}

func TestDeleteGroupNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.DeleteGroup(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteGroup missing error = %v, want ErrNotFound", err)
	}
}

func TestGroupDependents(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	group, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	sshProf, err := s.CreateSSH(ctx, SSHProfileForTest("web", "[]"))
	if err != nil {
		t.Fatal(err)
	}
	dbProf, err := s.CreateDB(ctx, DBProfileForTest("appdb", 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, "UPDATE ssh_connections SET group_id=? WHERE id=?", group.ID, sshProf.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, "UPDATE db_connections SET group_id=? WHERE id=?", group.ID, dbProf.ID); err != nil {
		t.Fatal(err)
	}

	deps, err := s.GroupDependents(ctx, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps.SSH) != 1 || deps.SSH[0].ID != sshProf.ID || deps.SSH[0].Name != "web" {
		t.Errorf("deps.SSH = %+v, want web %d", deps.SSH, sshProf.ID)
	}
	if len(deps.DB) != 1 || deps.DB[0].ID != dbProf.ID || deps.DB[0].Name != "appdb" {
		t.Errorf("deps.DB = %+v, want appdb %d", deps.DB, dbProf.ID)
	}
}

func TestGroupDependentsRejectsMissingGroup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.GroupDependents(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Errorf("GroupDependents missing error = %v, want ErrNotFound", err)
	}
}
