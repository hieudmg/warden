package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"warden/internal/crypto"
	"warden/internal/model"
	"warden/internal/server/setup"
	"warden/internal/store"
)

// Faults are test-local, scoped inside the already-authenticated managed
// handler. No production bypass, storage-engine abstraction, or old DEK input.
// Package tests are not parallel; rand.Reader is restored BEFORE TLS delivery.
type transferNonceFault struct {
	reader io.Reader
	calls  int
	fail   bool
	cancel context.CancelFunc
}

func (f *transferNonceFault) Read(b []byte) (int, error) {
	f.calls++
	if f.calls == 2 {
		if f.fail {
			return 0, errors.New("synthetic nonce failure")
		}
		f.cancel()
	}
	return f.reader.Read(b)
}

// Passing-existing characterization. Real TLS + real verifier signatures over
// issued challenges; synthetic credentials/PRF, NOT genuine browser PRF proof.
func TestHTTPSVersion1ImportPreservesIdentityAndFailureRetry(t *testing.T) {
	for _, fault := range []string{"none", "encryption", "SQL", "commit", "cancellation"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			p, _, initial, dek, signer := runtimeFixture(t)
			// Separate fresh initialized destination with a known disposable path for
			// SQL fault fixtures. Never open any account/real installation.
			raw, err := p.store.Installation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "fresh.db")
			if err = store.CommitInstallation(ctx, path, raw); err != nil {
				t.Fatal(err)
			}
			dest, err := store.OpenInitialized(ctx, path, func(b []byte) error { _, e := validateInstallation(b, p.cfg); return e }, p.vault)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { dest.Close() })
			p, err = newPlane(p.cfg, dest, initial, p.vault, p.verifier, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = p.updateIdentity(ctx, func(i *setup.Installation) error { i.AuthorizationGeneration = 9; return nil }, "", false); err != nil {
				t.Fatal(err)
			}
			raw, err = dest.Installation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			clientToken := crypto.Encode(bytes.Repeat([]byte{91}, 32))
			clientRecord := store.ClientCredential{ID: "existing-destination-client", Verifier: hash(clientToken), Label: "synthetic", Generation: 9, Created: 1}
			if err = dest.ApproveClient(ctx, raw, clientRecord); err != nil {
				t.Fatal(err)
			}
			mountProfiles(p)
			managed := p.managed
			armed := fault != "none"
			p.managed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !armed || r.URL.Path != "/api/v1/data/import" {
					managed.ServeHTTP(w, r)
					return
				}
				armed = false
				if fault == "encryption" || fault == "cancellation" {
					old := rand.Reader
					child, cancel := context.WithCancel(r.Context())
					defer cancel()
					rand.Reader = &transferNonceFault{reader: old, fail: fault == "encryption", cancel: cancel}
					defer func() { rand.Reader = old }()
					r = r.WithContext(child)
				}
				managed.ServeHTTP(w, r)
			})
			u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
			db, err := sql.Open("sqlite", u.String())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			cleanupSQL := func() {}
			switch fault {
			case "SQL":
				_, err = db.Exec(`CREATE TRIGGER transfer_fault BEFORE INSERT ON reports BEGIN SELECT RAISE(ABORT,'synthetic SQL failure'); END`)
				cleanupSQL = func() {
					if _, e := db.Exec(`DROP TRIGGER transfer_fault`); e != nil {
						t.Fatal(e)
					}
				}
			case "commit":
				_, err = db.Exec(`CREATE TABLE transfer_parent(id INTEGER PRIMARY KEY);
CREATE TABLE transfer_child(id INTEGER REFERENCES transfer_parent(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER transfer_fault AFTER INSERT ON connection_notes BEGIN INSERT INTO transfer_child VALUES (123); END;`)
				cleanupSQL = func() {
					if _, e := db.Exec(`DROP TRIGGER transfer_fault; DROP TABLE transfer_child; DROP TABLE transfer_parent`); e != nil {
						t.Fatal(e)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			cert, roots, _, _ := testCertificate(t, dir)
			server := httptest.NewUnstartedServer(p)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
			server.StartTLS()
			defer server.Close()
			address := server.Listener.Addr().String()
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}}
			defer transport.CloseIdleConnections()
			jar, _ := cookiejar.New(nil)
			client := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second}
			csrf := ""
			request := func(method, target string, body []byte, grant, bearer string) (int, []byte) {
				t.Helper()
				req, e := http.NewRequest(method, initial.PublicOrigin+target, bytes.NewReader(body))
				if e != nil {
					t.Fatal(e)
				}
				req.Header.Set("Content-Type", "application/json")
				if bearer != "" {
					req.Header.Set("Authorization", "Bearer "+bearer)
				} else {
					req.Header.Set("Origin", initial.PublicOrigin)
					req.Header.Set("X-CSRF-Token", csrf)
					req.Header.Set("X-Warden-Action", grant)
				}
				res, e := client.Do(req)
				if e != nil {
					t.Fatal(e)
				}
				defer res.Body.Close()
				data, e := io.ReadAll(res.Body)
				if e != nil {
					t.Fatal(e)
				}
				if res.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("missing no-store", target)
				}
				return res.StatusCode, data
			}
			post := func(target string, body any) []byte {
				t.Helper()
				b, e := json.Marshal(body)
				if e != nil {
					t.Fatal(e)
				}
				status, data := request("POST", "/api/v1/auth/"+target, b, "", "")
				if status != 200 {
					t.Fatalf("%s status %d %s", target, status, data)
				}
				return data
			}
			challenge := func(b []byte) (string, string) {
				t.Helper()
				var v struct {
					ID      string `json:"id"`
					Options struct {
						PublicKey struct {
							Challenge string `json:"challenge"`
						} `json:"publicKey"`
					} `json:"options"`
				}
				if json.Unmarshal(b, &v) != nil || v.Options.PublicKey.Challenge == "" {
					t.Fatal("missing challenge")
				}
				return v.ID, v.Options.PublicKey.Challenge
			}
			signedFinish := func(kind string, b []byte, signer *ecdsa.PrivateKey) []byte {
				t.Helper()
				id, c := challenge(b)
				signed := fixtureAssertion(t, signer, initial.Owner.Credentials[0].ID, initial.Owner.ID, c, initial.PublicOrigin, initial.RPID, true)
				return post(kind+"/finish", map[string]any{"id": id, "credential": json.RawMessage(signed)})
			}
			login := signedFinish("login", post("login/begin", struct{}{}), signer)
			var state struct {
				CSRF string `json:"csrf"`
			}
			if json.Unmarshal(login, &state) != nil || state.CSRF == "" {
				t.Fatal("no CSRF")
			}
			csrf = state.CSRF
			grantFor := func(action, method, target string, body []byte) string {
				t.Helper()
				result := signedFinish("fresh", post("fresh/begin", map[string]string{"action": action, "credential_id": initial.Passkey.CredentialID, "method": method, "path": target, "digest": hash(string(body))}), signer)
				var g struct {
					Grant string `json:"grant"`
				}
				if json.Unmarshal(result, &g) != nil || g.Grant == "" {
					t.Fatal("no grant")
				}
				return g.Grant
			}
			// Login works locked. Unlock is a separate signed assertion + DEK check.
			result := signedFinish("fresh", post("fresh/begin", map[string]string{"action": "unlock", "credential_id": initial.Passkey.CredentialID}), signer)
			var unlock struct {
				Grant string `json:"grant"`
			}
			json.Unmarshal(result, &unlock)
			post("unlock", map[string]string{"grant": unlock.Grant, "dek": crypto.Encode(dek)})
			payload, err := os.ReadFile("../../store/testdata/warden-data-v1-c104353.json")
			if err != nil {
				t.Fatal(err)
			}
			var want model.DataBundle
			if err = json.Unmarshal(payload, &want); err != nil {
				t.Fatal(err)
			}
			snapshot := func() []byte {
				t.Helper()
				identity, e := dest.Installation(ctx)
				if e != nil {
					t.Fatal(e)
				}
				clients, e := dest.Clients(ctx)
				if e != nil {
					t.Fatal(e)
				}
				// Seen may advance on legitimate auth; stable identity, session binding,
				// creation and complete client records must not be replaced by import.
				origin, _ := url.Parse(initial.PublicOrigin)
				var session store.Session
				for _, c := range jar.Cookies(origin) {
					if c.Name == sessionCookie {
						session, e = dest.Session(ctx, hash(c.Value))
						if e != nil {
							t.Fatal(e)
						}
					}
				}
				if session.Hash == "" {
					t.Fatal("no durable login session")
				}
				session.Seen = 0
				b, e := json.Marshal([]any{identity, clients, session})
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			g := grantFor("import", "POST", "/api/v1/data/import", payload)
			before := snapshot()
			status, data := request("POST", "/api/v1/data/import", payload, g, "")
			if fault != "none" {
				if status != 500 {
					t.Fatalf("fault %s status %d %s", fault, status, data)
				}
				empty, e := dest.ExportData(ctx)
				if e != nil || len(empty.Groups)+len(empty.KeyPairs)+len(empty.SSHConnections)+len(empty.DBConnections)+len(empty.Projects)+len(empty.Reports)+len(empty.ConnectionNotes) != 0 {
					t.Fatal("partial failed HTTP import", e)
				}
				if !bytes.Equal(before, snapshot()) {
					t.Fatal("failed HTTP import replaced auth")
				}
				cleanupSQL()
				g = grantFor("import", "POST", "/api/v1/data/import", payload)
				before = snapshot()
				status, data = request("POST", "/api/v1/data/import", payload, g, "")
			}
			if status != 204 {
				t.Fatalf("import %d %s", status, data)
			}
			if !bytes.Equal(before, snapshot()) {
				t.Fatal("successful HTTP import replaced auth")
			}
			exported, e := dest.ExportData(ctx)
			if e != nil {
				t.Fatal(e)
			}
			exported.ExportedAt = want.ExportedAt
			if !reflect.DeepEqual(exported, want) {
				t.Fatal("complete historical dataset not preserved")
			}
			if status, data = request("GET", "/api/v1/client/ssh-connections", nil, "", clientToken); status != 200 || !bytes.Contains(data, []byte("password-host")) {
				t.Fatal("existing generation-bound client no longer works", status, string(data))
			}
			g = grantFor("export", "GET", "/api/v1/data/export", nil)
			status, data = request("GET", "/api/v1/data/export", nil, g, "")
			if status != 200 {
				t.Fatal("fresh export", status)
			}
			var public map[string]json.RawMessage
			if json.Unmarshal(data, &public) != nil || len(public) != 10 {
				t.Fatal("unexpected transfer collections or auth leak", len(public))
			}
			for _, name := range []string{"installation", "passkey_wrappers", "web_sessions", "client_credentials", "authorization_generation", "recovery_wrapper"} {
				if _, ok := public[name]; ok {
					t.Fatal("auth exported", name)
				}
			}
			var round model.DataBundle
			if json.Unmarshal(data, &round) != nil {
				t.Fatal("export JSON")
			}
			round.ExportedAt = want.ExportedAt
			if !reflect.DeepEqual(round, want) {
				t.Fatal("HTTPS export fidelity")
			}
			g = grantFor("import", "POST", "/api/v1/data/import", payload)
			before = snapshot()
			status, data = request("POST", "/api/v1/data/import", payload, g, "")
			if status != 409 || !strings.Contains(string(data), "destination already contains managed data") {
				t.Fatal("nonempty refusal", status, string(data))
			}
			if !bytes.Equal(before, snapshot()) {
				t.Fatal("nonempty import replaced auth")
			}
			after, e := dest.ExportData(ctx)
			if e != nil {
				t.Fatal(e)
			}
			after.ExportedAt = want.ExportedAt
			if !reflect.DeepEqual(after, want) {
				t.Fatal("nonempty destination overwritten")
			}
		})
	}
}
