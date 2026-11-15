package profiles_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"warden/internal/model"
	"warden/internal/server/profiles"
	"warden/internal/store"
)

// One root occurrence plus each traversed edge (duplicates included), before
// lookup/recursion. DB roots consume one too; depth counts SSH nodes only.
func TestResolveDuplicateDAGCumulativeBudget(t *testing.T) {
	_, s, _ := newTestAPI(t)
	node := createSSH(t, s, "leaf", "[]")
	// Only 11 rows, but 2^11-1 expanded occurrences. Finite even before fix.
	for i := 1; i < 11; i++ {
		node = createSSH(t, s, fmt.Sprintf("level-%d", i), fmt.Sprintf("[%d,%d]", node.ID, node.ID))
	}
	b, err := profiles.NewResolver(s).ResolveSSHBundle(context.Background(), node.ID)
	var ge *profiles.GraphError
	if !errors.As(err, &ge) {
		t.Fatalf("2047 occurrences: error=%v, jumps=%d; want bounded graph failure", err, len(b.Jumps))
	}
	if b.Target.ID != 0 || len(b.Jumps) != 0 {
		t.Fatal("partial bundle")
	}
}

func TestTransportGraphFailuresSafeClassification(t *testing.T) {
	mux, s, path := newTestAPI(t)
	leaf := createSSH(t, s, "leaf", "[]")
	root := createSSH(t, s, "root", "[]")
	// A numeric exponent causes encoding/json to include the supplied number
	// in its raw conversion error. Neither response nor audit may retain it.
	marker := "1234567890123456789012345678901234567890"
	for _, route := range []string{"[1e" + marker + "]", repeatExternalRoute(leaf.ID, 1024)} {
		if _, err := rawDB(t, path).Exec("UPDATE ssh_connections SET jump_connection_ids=? WHERE id=?", route, root.ID); err != nil {
			t.Fatal(err)
		}
		for _, tunnel := range []bool{false, true} {
			endpoint := fmt.Sprintf("/api/v1/transport/ssh/%d", root.ID)
			if tunnel {
				db := createDB(t, s, fmt.Sprintf("db-%d", len(route)), root.ID)
				endpoint = fmt.Sprintf("/api/v1/transport/db/%d", db.ID)
			}
			rec := doRequest(t, mux, "GET", endpoint, "")
			if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `"code":"invalid_graph"`) {
				t.Fatalf("graph status=%d body=%s", rec.Code, rec.Body.String())
			}
			event := lastAuditEvent(t, path)
			if event.Result != "failure" || event.Error == "" || strings.Contains(event.Error, marker) || strings.Contains(rec.Body.String(), marker) {
				t.Fatalf("unsafe graph failure: audit=%s response=%s", event.Error, rec.Body.String())
			}
		}
	}
}

func repeatExternalRoute(id int64, n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(fmt.Sprintf("%d,", id), n), ",") + "]"
}

func TestResolveBudgetBoundaryRealStore(t *testing.T) {
	_, s, _ := newTestAPI(t)
	leaf := createSSH(t, s, "leaf", "[]")
	root := createSSH(t, s, "root", "[]")
	db := createDB(t, s, "db", root.ID)
	for _, tunnel := range []bool{false, true} {
		for _, total := range []int{1024, 1025} {
			root.JumpConnectionIDs = repeatExternalRoute(leaf.ID, total-1)
			if tunnel {
				root.JumpConnectionIDs = repeatExternalRoute(leaf.ID, total-2)
			}
			if err := s.UpdateSSH(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			var err error
			var jumps []model.SSHNode
			if tunnel {
				var b model.DBBundle
				b, err = profiles.NewResolver(s).ResolveDBBundle(context.Background(), db.ID)
				if b.SSH != nil {
					jumps = b.SSH.Jumps
				}
			} else {
				var b model.SSHBundle
				b, err = profiles.NewResolver(s).ResolveSSHBundle(context.Background(), root.ID)
				jumps = b.Jumps
			}
			if total == 1025 {
				if !errors.Is(err, profiles.ErrJumpBudgetExceeded) || len(jumps) != 0 {
					t.Fatalf("overflow tunnel=%v: jumps=%d err=%v", tunnel, len(jumps), err)
				}
				continue
			}
			want := 1023
			if tunnel {
				want--
			}
			if err != nil || len(jumps) != want {
				t.Fatalf("boundary tunnel=%v: jumps=%d err=%v", tunnel, len(jumps), err)
			}
			for _, hop := range jumps {
				if hop.ID != leaf.ID || string(hop.Password) != "pw-leaf" {
					t.Fatal("duplicate or secret changed")
				}
			}
		}
	}
}

func TestResolveBudgetPreservesOrderAndDuplicates(t *testing.T) {
	_, s, _ := newTestAPI(t)
	a := createSSH(t, s, "a", "[]")
	b := createSSH(t, s, "b", fmt.Sprintf("[%d]", a.ID))
	root := createSSH(t, s, "root", fmt.Sprintf("[%d,%d,%d]", b.ID, a.ID, b.ID))
	bundle, err := profiles.NewResolver(s).ResolveSSHBundle(context.Background(), root.ID)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, n := range bundle.Jumps {
		ids = append(ids, n.ID)
		if len(n.Password) == 0 {
			t.Fatal("missing hop password")
		}
	}
	if !reflect.DeepEqual(ids, []int64{a.ID, b.ID, a.ID, a.ID, b.ID}) {
		t.Fatalf("postorder=%v", ids)
	}
}

func TestResolveInvalidGraphBeforeAnySecretDecrypt(t *testing.T) {
	for _, kind := range []string{"missing", "archived-target", "archived-hop", "cycle", "malformed", "db-tunnel"} {
		t.Run(kind, func(t *testing.T) {
			_, s, path := newTestAPI(t)
			ctx := context.Background()
			hop := createSSH(t, s, "hop", "[]")
			root := createSSH(t, s, "root", fmt.Sprintf("[%d,999999]", hop.ID))
			switch kind {
			case "archived-target":
				if err := s.SetSSHArchived(ctx, root.ID, true); err != nil {
					t.Fatal(err)
				}
			case "archived-hop":
				if err := s.SetSSHArchived(ctx, hop.ID, true); err != nil {
					t.Fatal(err)
				}
			case "cycle":
				root.JumpConnectionIDs = fmt.Sprintf("[%d]", root.ID)
				if err := s.UpdateSSH(ctx, root); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if _, err := rawDB(t, path).Exec("UPDATE ssh_connections SET jump_connection_ids=? WHERE id=?", `["route-secret-marker"]`, root.ID); err != nil {
					t.Fatal(err)
				}
			}
			// Corrupt selected hop key material as well as the target password.
			// The graph must win over either kind of secret corruption.
			pair, e := s.CreateKeyPair(ctx, model.KeyPair{Name: "pair", PrivateKey: []byte("synthetic key")})
			if e != nil {
				t.Fatal(e)
			}
			hop.Password = nil
			hop.KeyPairID = pair.ID
			if e = s.UpdateSSH(ctx, hop); e != nil {
				t.Fatal(e)
			}
			if _, e = rawDB(t, path).Exec("UPDATE key_pairs SET private_key=x'01' WHERE id=?", pair.ID); e != nil {
				t.Fatal(e)
			}
			corruptPassword(t, path, root.ID)
			var err error
			if kind == "db-tunnel" {
				db := createDB(t, s, "db", root.ID)
				if _, e := rawDB(t, path).Exec("UPDATE db_connections SET password=x'01' WHERE id=?", db.ID); e != nil {
					t.Fatal(e)
				}
				var bundle model.DBBundle
				bundle, err = profiles.NewResolver(s).ResolveDBBundle(ctx, db.ID)
				if bundle.Host != "" || bundle.SSH != nil {
					t.Fatal("partial DB bundle")
				}
			} else {
				var bundle model.SSHBundle
				bundle, err = profiles.NewResolver(s).ResolveSSHBundle(ctx, root.ID)
				if bundle.Target.ID != 0 || len(bundle.Jumps) != 0 {
					t.Fatal("partial SSH bundle")
				}
			}
			if strings.Contains(fmt.Sprint(err), "route-secret-marker") {
				t.Fatal("raw route in graph error")
			}
			if strings.HasPrefix(kind, "archived") {
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("want not found before decrypt, got %v", err)
				}
			} else {
				var ge *profiles.GraphError
				if !errors.As(err, &ge) {
					t.Fatalf("want structural failure before decrypt, got %v", err)
				}
			}
		})
	}
}
