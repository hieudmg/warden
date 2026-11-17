package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"warden/internal/server/setup"
)

func TestAccountStalePasswordWorkCannotPublish(t *testing.T) {
	for _, operation := range []string{"login", "unlock", "fresh"} {
		for _, boundary := range []string{"lock", "logout", "identity", "recovery", "cancel"} {
			t.Run(operation+"/"+boundary, func(t *testing.T) {
				p, _ := accountFixture(t)
				c, csrf := accountLogin(t, p, accountPassword)
				entered, release := make(chan struct{}), make(chan struct{})
				defer func() {
					select {
					case <-release:
					default:
						close(release)
					}
				}()
				p.beforeAccountPublish = func(*http.Request) { close(entered); <-release }
				body := map[string]string{"password": accountPassword}
				if operation == "login" {
					body["username"] = "owner"
				}
				if operation == "fresh" {
					body["action"] = "export"
					body["method"] = "GET"
					body["path"] = "/api/v1/data/export"
					body["digest"] = hash("")
				}
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", "https://warden.example/api/v1/auth/account/"+operation, bytes.NewReader(raw))
				r.Header.Set("Origin", p.cfg.PublicOrigin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-CSRF-Token", csrf)
				r.AddCookie(c)
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { w := httptest.NewRecorder(); p.ServeHTTP(w, r); done <- w }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("KDF blocked with mutex held")
				}
				switch boundary {
				case "lock":
					p.vault.Lock()
				case "logout":
					if w := call(p, "POST", "/api/v1/auth/logout", struct{}{}, c, csrf); w.Code != 200 {
						t.Fatal(w.Code)
					}
				case "identity":
					if e := p.updateIdentity(context.Background(), func(i *setup.Installation) error { return nil }, "", true); e != nil {
						t.Fatal(e)
					}
				case "recovery":
					p.mu.Lock()
					p.recoveryRun = "reserved"
					p.mu.Unlock()
				case "cancel":
					cancel()
				}
				close(release)
				select {
				case w := <-done:
					if w.Code == 200 {
						t.Fatal("stale password result published", w.Body)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("request hung")
				}
				if len(p.grants) != 0 {
					t.Fatal("stale grant published")
				}
				if boundary == "lock" && p.vault.Unlocked() {
					t.Fatal("resurrected key")
				}
			})
		}
	}
}
func TestAccountAdmissionBeforeBodyRead(t *testing.T) {
	p, _ := accountFixture(t)
	for n := 0; n < cap(p.keyOperations); n++ {
		p.keyOperations <- struct{}{}
	}
	r := httptest.NewRequest("POST", "https://warden.example/api/v1/auth/account/login", nil)
	r.Header.Set("Origin", p.cfg.PublicOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.Body = &panicReadBody{}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal("not bounded", w.Code)
	}
}

type panicReadBody struct{}

func (*panicReadBody) Read([]byte) (int, error) { panic("read before admission") }
func (*panicReadBody) Close() error             { return nil }
func TestAccountIdentityModeValidation(t *testing.T) {
	p, _ := accountFixture(t)
	raw, _ := json.Marshal(p.install)
	for _, change := range []func(*setup.Installation){func(i *setup.Installation) { i.AuthMethod = "" }, func(i *setup.Installation) { i.AuthMethod = "passkey" }, func(i *setup.Installation) { i.AuthMethod = "none" }, func(i *setup.Installation) { i.Account = nil }, func(i *setup.Installation) { i.Account.ID = "bad" }} {
		var i setup.Installation
		json.Unmarshal(raw, &i)
		change(&i)
		bad, _ := json.Marshal(i)
		if _, e := validateInstallation(bad, p.cfg); e == nil {
			t.Fatal("mixed/malformed identity")
		}
	}
	cfg := p.cfg
	cfg.AuthMethod = "passkey"
	if _, e := validateInstallation(raw, cfg); e == nil {
		t.Fatal("mode conversion")
	}
}
