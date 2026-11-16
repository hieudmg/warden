package audit_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"warden/internal/crypto"
	"warden/internal/server/audit"
	"warden/internal/store"
)

func auditFixture(t *testing.T) (*audit.Recorder, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := store.Open(context.Background(), path, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return audit.New(s), db
}

func TestAuditClassificationsAllowlist(t *testing.T) {
	recorder, db := auditFixture(t)
	const secret = "synthetic-error-secret"
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"success", nil, ""},
		{"validation", fmt.Errorf("%w: %s", store.ErrValidation, secret), "validation"},
		{"not found", fmt.Errorf("%w: %s", store.ErrNotFound, secret), "not_found"},
		{"duplicate", fmt.Errorf("%w: %s", store.ErrDuplicate, secret), "conflict"},
		{"locked", fmt.Errorf("%w: %s", crypto.ErrVaultLocked, secret), "locked"},
		{"unknown", errors.New(secret), "internal"},
		{"cancelled", context.Canceled, "cancelled"},
		{"deadline", context.DeadlineExceeded, "timeout"},
		{"invalid json", audit.InvalidJSON, "invalid_json"},
		{"invalid graph", audit.InvalidGraph, "invalid_graph"},
		{"auth", audit.Unauthorized, "unauthorized"},
		{"rate", audit.RateLimited, "rate_limited"},
		{"storage", audit.Storage, "storage"},
		{"internal", audit.Internal, "internal"},
		{"oversized", audit.PayloadTooLarge, "payload_too_large"},
		{"forged classification", audit.Classification(secret), "internal"},
		{"no Error call", opaqueError{}, "internal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := recorder.Record(context.Background(), "ssh_connection.get", "ssh_connection", "17", "127.0.0.1:42", "failure", tc.err, nil); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := db.QueryRow("SELECT error FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("classification=%q want=%q", got, tc.want)
			}
		})
	}
}

type opaqueError struct{}

func (opaqueError) Error() string { panic("audit must not call unknown Error") }

type forbiddenMetadata struct{ calls *int }

func (v forbiddenMetadata) MarshalJSON() ([]byte, error) {
	*v.calls++
	return []byte(`"synthetic-marshaler-secret"`), nil
}
func (v forbiddenMetadata) String() string { *v.calls++; return "synthetic-stringer-secret" }

func TestAuditMetadataCapsAndNoCallerMutation(t *testing.T) {
	recorder, db := auditFixture(t)
	for _, ua := range []string{strings.Repeat("界", 171), strings.Repeat("<", 2000), "agent\n\x1b\xff"} {
		req := httptest.NewRequest("GET", "https://warden.example/", nil)
		req.Header.Set("User-Agent", ua)
		if err := recorder.RecordRequest(req.Context(), req, "data.export", "data", "", "success", nil, nil); err != nil {
			t.Fatal(err)
		}
		var encoded string
		if err := db.QueryRow("SELECT metadata FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(encoded), &got); err != nil {
			t.Fatal(err)
		}
		bounded, _ := got["user_agent"].(string)
		if len(encoded) > 4096 || len(bounded) > 512 || !utf8.ValidString(bounded) || strings.ContainsAny(bounded, "\n\x1b\ufffd") {
			t.Error("UA/encoded metadata unbounded or unsafe")
		}
	}
	calls := 0
	nested := map[string]any{}
	nested["cycle"] = nested
	metadata := map[string]any{
		"archived": true, "groups": 7, "reports": 3,
		"user_agent":    "caller-original",
		"credential_id": strings.Repeat("A", 1366),
		"name":          "synthetic-unknown-secret",
		"project":       "synthetic-unknown-secret", "agent_model": "synthetic-unknown-secret",
		"nested": nested, "unserializable": make(chan int),
		"db_connections":  forbiddenMetadata{&calls},
		"ssh_connections": strings.Repeat("synthetic-huge-secret", 1<<16),
	}
	before := make(map[string]any, len(metadata))
	for k, v := range metadata {
		before[k] = v
	}
	req := httptest.NewRequest("GET", "https://warden.example/", nil)
	req = req.WithContext(audit.WithActor(req.Context(), audit.Actor{CredentialID: strings.Repeat("A", 1366), ClientCredentialID: "client-safe-id"}))
	req.RemoteAddr = "192.0.2.9:1234"
	req.Header.Set("User-Agent", strings.Repeat("界", 171)+"\xff\n")
	req.Header.Set("Forwarded", "for=synthetic-forwarded-secret")
	req.Header.Set("X-Forwarded-For", "synthetic-forwarded-secret")
	req.Header.Set("X-Warden-Credential-ID", "synthetic-header-actor-secret")
	if err := recorder.RecordRequest(req.Context(), req, "data.export", "data", "", "success", nil, metadata); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(metadata, before) {
		t.Error("caller metadata mutated")
	}
	if calls != 0 {
		t.Errorf("invoked arbitrary metadata methods %d times", calls)
	}
	var encoded, source string
	if err := db.QueryRow("SELECT metadata,source FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&encoded, &source); err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 4096 || !utf8.ValidString(encoded) {
		t.Errorf("invalid metadata size/UTF-8: %d bytes", len(encoded))
	}
	if source != req.RemoteAddr {
		t.Errorf("source=%q", source)
	}
	if strings.Contains(encoded+source, "synthetic-forwarded-secret") || strings.Contains(encoded, "synthetic-header-actor-secret") {
		t.Error("untrusted source/actor headers retained")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(encoded), &got); err != nil {
		t.Fatal(err)
	}
	ua, _ := got["user_agent"].(string)
	if len(ua) != 510 || !utf8.ValidString(ua) || strings.ContainsAny(ua, "\n\xff") {
		t.Errorf("invalid UA: bytes=%d", len(ua))
	}
	for _, key := range []string{"name", "project", "agent_model", "nested", "unserializable", "db_connections", "ssh_connections"} {
		if _, ok := got[key]; ok {
			t.Errorf("unsafe key retained: %s", key)
		}
	}
	if got["credential_id"] != strings.Repeat("A", 1366) || got["client_credential_id"] != "client-safe-id" {
		t.Error("nonsecret actor identifiers lost")
	}
	if got["archived"] != true || got["groups"] != float64(7) {
		t.Error("safe primitive metadata lost")
	}
	// JSON escaping, not rune count, determines the final budget.
	req.Header.Set("User-Agent", strings.Repeat("<", 512))
	if err := recorder.RecordRequest(req.Context(), req, "data.export", "data", "", "success", nil, metadata); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT metadata FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 4096 {
		t.Errorf("JSON escaped metadata exceeds 4KiB: %d", len(encoded))
	}
	if err := json.Unmarshal([]byte(encoded), &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, `"user_agent"`) {
		t.Error("overflowing encoded UA must be omitted, not truncate unknown values")
	}
	if got["credential_id"] != strings.Repeat("A", 1366) {
		t.Error("encoded cap dropped actor")
	}
	// No processing of arbitrarily deep/cyclic values, even under allowed keys.
	bad := map[string]any{"user_agent": nested, "archived": forbiddenMetadata{&calls}, "reports": make(chan int)}
	if err := recorder.Record(context.Background(), "data.export", "data", "", "synthetic-source-secret\n", "success", nil, bad); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT metadata,source FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&encoded, &source); err != nil {
		t.Fatal(err)
	}
	if encoded != "{}" || source != "" || calls != 0 {
		t.Errorf("unsafe structure/source retained or executed: metadata=%s source=%q calls=%d", encoded, source, calls)
	}
}
