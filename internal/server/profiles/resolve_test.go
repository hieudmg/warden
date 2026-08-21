package profiles_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"warden/internal/server/profiles"
)

func TestResolveSSHBundleLinearChain(t *testing.T) {
	_, s, _ := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	j1 := createSSH(t, s, "j1", "[]")
	j2 := createSSH(t, s, "j2", "[]")
	target := createSSH(t, s, "target", fmt.Sprintf("[%d, %d]", j1.ID, j2.ID))

	bundle, err := r.ResolveSSHBundle(ctx, target.ID)
	if err != nil {
		t.Fatalf("ResolveSSHBundle: %v", err)
	}
	if bundle.Target.ID != target.ID {
		t.Errorf("target id = %d, want %d", bundle.Target.ID, target.ID)
	}
	if len(bundle.Jumps) != 2 {
		t.Fatalf("jumps = %d, want 2", len(bundle.Jumps))
	}
	if bundle.Jumps[0].ID != j1.ID || bundle.Jumps[1].ID != j2.ID {
		t.Errorf("jump order = [%d %d], want [%d %d]",
			bundle.Jumps[0].ID, bundle.Jumps[1].ID, j1.ID, j2.ID)
	}
	if string(bundle.Target.Password) != "pw-target" {
		t.Errorf("target password = %q, want decrypted pw-target", bundle.Target.Password)
	}
	if string(bundle.Jumps[0].Password) != "pw-j1" {
		t.Errorf("jump password = %q, want decrypted pw-j1", bundle.Jumps[0].Password)
	}
}

func TestResolveSSHBundleNestedJumps(t *testing.T) {
	_, s, _ := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	j2 := createSSH(t, s, "j2", "[]")
	j1 := createSSH(t, s, "j1", fmt.Sprintf("[%d]", j2.ID))
	target := createSSH(t, s, "target", fmt.Sprintf("[%d]", j1.ID))

	bundle, err := r.ResolveSSHBundle(ctx, target.ID)
	if err != nil {
		t.Fatalf("ResolveSSHBundle: %v", err)
	}
	// Route: reach j1 through j2, then j1, then target.
	if len(bundle.Jumps) != 2 {
		t.Fatalf("jumps = %d, want 2", len(bundle.Jumps))
	}
	if bundle.Jumps[0].ID != j2.ID || bundle.Jumps[1].ID != j1.ID {
		t.Errorf("jump order = [%d %d], want [%d %d]",
			bundle.Jumps[0].ID, bundle.Jumps[1].ID, j2.ID, j1.ID)
	}
}

func TestResolveSSHBundleMissingID(t *testing.T) {
	_, s, _ := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	target := createSSH(t, s, "target", "[999999]")

	bundle, err := r.ResolveSSHBundle(ctx, target.ID)
	if err == nil {
		t.Fatal("ResolveSSHBundle succeeded with a missing jump id")
	}
	var ge *profiles.GraphError
	if !errors.As(err, &ge) {
		t.Errorf("error %v is not a GraphError", err)
	}
	if bundle.Target.ID != 0 || len(bundle.Jumps) != 0 {
		t.Errorf("partial bundle returned on failure: %+v", bundle)
	}
}

func TestResolveSSHBundleSelfReference(t *testing.T) {
	_, s, _ := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	target := createSSH(t, s, "target", "[]")
	target.JumpConnectionIDs = fmt.Sprintf("[%d]", target.ID)
	if err := s.UpdateSSH(ctx, target); err != nil {
		t.Fatalf("UpdateSSH: %v", err)
	}

	_, err := r.ResolveSSHBundle(ctx, target.ID)
	if err == nil {
		t.Fatal("ResolveSSHBundle succeeded with a self-referencing route")
	}
	var ge *profiles.GraphError
	if !errors.As(err, &ge) {
		t.Errorf("error %v is not a GraphError", err)
	}
}

func TestResolveSSHBundleCycle(t *testing.T) {
	_, s, _ := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	j1 := createSSH(t, s, "j1", "[]")
	target := createSSH(t, s, "target", fmt.Sprintf("[%d]", j1.ID))
	j1.JumpConnectionIDs = fmt.Sprintf("[%d]", target.ID)
	if err := s.UpdateSSH(ctx, j1); err != nil {
		t.Fatalf("UpdateSSH: %v", err)
	}

	_, err := r.ResolveSSHBundle(ctx, target.ID)
	if err == nil {
		t.Fatal("ResolveSSHBundle succeeded with a cycle")
	}
	var ge *profiles.GraphError
	if !errors.As(err, &ge) {
		t.Errorf("error %v is not a GraphError", err)
	}
}

func TestResolveSSHBundleMalformedStoredJSON(t *testing.T) {
	_, s, path := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	target := createSSH(t, s, "target", "[]")
	corruptJumpIDs(t, path, target.ID)

	_, err := r.ResolveSSHBundle(ctx, target.ID)
	if err == nil {
		t.Fatal("ResolveSSHBundle succeeded with malformed stored jump JSON")
	}
	var ge *profiles.GraphError
	if !errors.As(err, &ge) {
		t.Errorf("error %v is not a GraphError", err)
	}
}

func TestResolveSSHBundleDecryptionFailure(t *testing.T) {
	_, s, path := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	target := createSSH(t, s, "target", "[]")
	corruptPassword(t, path, target.ID)

	_, err := r.ResolveSSHBundle(ctx, target.ID)
	if err == nil {
		t.Fatal("ResolveSSHBundle succeeded with a corrupted secret blob")
	}
	var ge *profiles.GraphError
	if errors.As(err, &ge) {
		t.Errorf("decryption failure misclassified as GraphError: %v", err)
	}
}

func TestResolveSSHBundleAADMismatch(t *testing.T) {
	_, s, path := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	a := createSSH(t, s, "a", "[]")
	b := createSSH(t, s, "b", "[]")
	swapPasswords(t, path, a.ID, b.ID)

	if _, err := r.ResolveSSHBundle(ctx, a.ID); err == nil {
		t.Fatal("ResolveSSHBundle succeeded after AAD-broken password swap")
	}
	if _, err := r.ResolveSSHBundle(ctx, b.ID); err == nil {
		t.Fatal("ResolveSSHBundle succeeded after AAD-broken password swap")
	}
}

func TestResolveSSHBundleRejectsChainExceedingMaxJumpDepth(t *testing.T) {
	_, s, _ := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	// Build a linear chain of MaxJumpDepth+1 rows: target -> j1 -> ... -> jN.
	// Created in reverse so each node references the next one down.
	const n = profiles.MaxJumpDepth
	next := "[]"
	for i := n; i >= 1; i-- {
		node := createSSH(t, s, fmt.Sprintf("j%d", i), next)
		next = fmt.Sprintf("[%d]", node.ID)
	}
	target := createSSH(t, s, "target", next)

	bundle, err := r.ResolveSSHBundle(ctx, target.ID)
	if !errors.Is(err, profiles.ErrJumpDepthExceeded) {
		t.Fatalf("ResolveSSHBundle error = %v, want ErrJumpDepthExceeded", err)
	}
	var ge *profiles.GraphError
	if !errors.As(err, &ge) {
		t.Errorf("depth error %v is not a GraphError", err)
	}
	if bundle.Target.ID != 0 || len(bundle.Jumps) != 0 {
		t.Errorf("partial bundle returned on depth failure: %+v", bundle)
	}
}

func TestResolveDBBundleDirect(t *testing.T) {
	_, s, _ := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	dbp := createDB(t, s, "direct", 0)
	bundle, err := r.ResolveDBBundle(ctx, dbp.ID)
	if err != nil {
		t.Fatalf("ResolveDBBundle: %v", err)
	}
	if bundle.SSH != nil {
		t.Errorf("direct DB bundle has SSH graph: %+v", bundle.SSH)
	}
	if string(bundle.Password) != "dbpw-direct" {
		t.Errorf("db password = %q, want decrypted dbpw-direct", bundle.Password)
	}
}

func TestResolveDBBundleOverSSH(t *testing.T) {
	_, s, _ := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	target := createSSH(t, s, "target", "[]")
	dbp := createDB(t, s, "tunneled", target.ID)

	bundle, err := r.ResolveDBBundle(ctx, dbp.ID)
	if err != nil {
		t.Fatalf("ResolveDBBundle: %v", err)
	}
	if bundle.SSH == nil {
		t.Fatal("tunneled DB bundle missing SSH graph")
	}
	if bundle.SSH.Target.ID != target.ID {
		t.Errorf("ssh target id = %d, want %d", bundle.SSH.Target.ID, target.ID)
	}
	if string(bundle.SSH.Target.Password) != "pw-target" {
		t.Errorf("ssh target password = %q, want decrypted pw-target", bundle.SSH.Target.Password)
	}
}

func TestResolveDBBundleMissingSSH(t *testing.T) {
	_, s, _ := newTestAPI(t)
	r := profiles.NewResolver(s)
	ctx := context.Background()

	dbp := createDB(t, s, "broken", 999999)
	_, err := r.ResolveDBBundle(ctx, dbp.ID)
	if err == nil {
		t.Fatal("ResolveDBBundle succeeded with a missing SSH reference")
	}
}
