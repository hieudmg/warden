package runtime

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/crypto"
	"warden/internal/server/audit"
	"warden/internal/server/profiles"
	"warden/internal/store"
)

func TestAuditNeverPersistsRawValidationValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	p, _, installation, key, signer := runtimeFixture(t, path)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	cookie, csrf := sessionFor(t, p)
	const secret = "synthetic-T8-auth-proof-secret"
	for _, tc := range []struct {
		path           string
		body           any
		authenticated  bool
		want           int
		classification string
	}{
		{"/api/v1/auth/recovery/proof", map[string]string{"id": secret, "proof": secret}, false, 403, "unauthorized"},
		{"/api/v1/auth/login/finish", map[string]any{"id": secret, "credential": map[string]string{"rawId": secret}}, false, 403, "unauthorized"},
		{"/api/v1/auth/unlock", map[string]string{"dek": secret, "grant": secret}, true, 403, "unauthorized"},
		{"/api/v1/client/poll", map[string]string{"id": secret, "poll_secret": secret}, false, 403, "unauthorized"},
		{"/api/v1/auth/passkeys/begin", map[string]string{"proof": secret}, true, 423, "locked"},
		{"/api/v1/auth/lock", map[string]any{}, true, 200, ""},
	} {
		var c *http.Cookie
		if tc.authenticated {
			c = cookie
		}
		w := call(p, "POST", tc.path, tc.body, c, csrf)
		if w.Code != tc.want {
			t.Fatalf("%s status=%d want=%d", tc.path, w.Code, tc.want)
		}
		var op, metadata, classification string
		if err := db.QueryRow("SELECT operation,metadata,error FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&op, &metadata, &classification); err != nil {
			t.Errorf("%s: no persisted auth event: %v", tc.path, err)
			continue
		}
		if op == "" || classification != tc.classification {
			t.Errorf("%s classification=%q want=%q", tc.path, classification, tc.classification)
		}
		if tc.authenticated && !strings.Contains(metadata, p.install.Passkey.CredentialID) {
			t.Error("validated actor credential ID absent")
		}
		for _, raw := range []string{secret, cookie.Value, csrf, hash(cookie.Value)} {
			if strings.Contains(op+metadata+classification+logs.String(), raw) {
				t.Error("auth proof/token/full verifier leaked")
			}
		}
	}
	loginCookie, loginCSRF := loginSigner(t, p, signer, installation.Owner.Credentials[0].ID)
	var loginMetadata, loginError string
	if err := db.QueryRow("SELECT metadata,error FROM audit_events WHERE operation='auth.login.finish' ORDER BY id DESC LIMIT 1").Scan(&loginMetadata, &loginError); err != nil {
		t.Fatal(err)
	}
	if loginError != "" || !strings.Contains(loginMetadata, installation.Passkey.CredentialID) {
		t.Error("successful signed login lost classification/actor")
	}
	now := p.now()
	p.now = func() time.Time { return now }
	p.tokens = 0
	p.refill = now
	if w := call(p, "POST", "/api/v1/auth/login/begin", struct{}{}, nil, ""); w.Code != 429 {
		t.Fatalf("rate status=%d", w.Code)
	}
	var rate string
	if err := db.QueryRow("SELECT error FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&rate); err != nil || rate != "rate_limited" {
		t.Fatal("rate audit missing or misclassified")
	}
	p.tokens = 10 // End the intentional saturation fixture before recovery.
	// Client actor metadata is its nonsecret durable ID, never its verifier.
	raw := crypto.Encode(bytes.Repeat([]byte{61}, 32))
	pairing := call(p, "POST", "/api/v1/client/pairing", map[string]string{"commitment": hash(raw), "label": secret}, nil, "")
	if pairing.Code != 200 {
		t.Fatalf("pairing status=%d", pairing.Code)
	}
	var paired struct {
		PollSecret string `json:"poll_secret"`
	}
	if err := json.Unmarshal(pairing.Body.Bytes(), &paired); err != nil {
		t.Fatal(err)
	}
	if paired.PollSecret == "" {
		t.Fatal("missing polling secret fixture")
	}
	identity, err := p.store.Installation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.store.ApproveClient(context.Background(), identity, store.ClientCredential{ID: "client-safe-id", Verifier: hash(raw), Label: secret, Generation: p.install.AuthorizationGeneration, Created: p.now().Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := p.vault.Unlock(key, p.vault.Generation()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	profiles.New(p.store, audit.New(p.store)).RegisterClient(mux)
	p.clientManaged = mux
	req := httptest.NewRequest("GET", "https://warden.example/api/v1/client/ssh-connections", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("client status=%d", w.Code)
	}
	var metadata string
	if err := db.QueryRow("SELECT metadata FROM audit_events WHERE operation='ssh_connection.list' ORDER BY id DESC LIMIT 1").Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(metadata, "client-safe-id") || strings.Contains(metadata, raw) || strings.Contains(metadata, hash(raw)) || strings.Contains(metadata, secret) {
		t.Error("client actor absent or credentials/label leaked")
	}
	root, proof := recoveryFixture(t, p, key)
	recoveryCookie, recoveryCSRF, recoveryGrant := startRecovery(t, p, proof)
	var recoveryError string
	if err := db.QueryRow("SELECT error FROM audit_events WHERE operation='auth.recovery.proof' ORDER BY id DESC LIMIT 1").Scan(&recoveryError); err != nil || recoveryError != "" {
		t.Fatal("successful recovery proof not audited")
	}
	rows, err := db.Query("SELECT operation,resource_type,resource_id,source,result,error,metadata FROM audit_events")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var columns [7]string
		if err := rows.Scan(&columns[0], &columns[1], &columns[2], &columns[3], &columns[4], &columns[5], &columns[6]); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{secret, cookie.Value, csrf, hash(cookie.Value), loginCookie.Value, loginCSRF, hash(loginCookie.Value), raw, hash(raw), paired.PollSecret, crypto.Encode(key), crypto.Encode(root), crypto.Encode(proof), recoveryCookie.Value, recoveryCSRF, recoveryGrant} {
			if strings.Contains(strings.Join(columns[:], " ")+logs.String(), value) {
				t.Error("persisted row/slog retained auth key, token, proof, label or full verifier")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
