package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"warden/internal/crypto"
)

func TestAccountRecoveryAbortPreservesIdentity(t *testing.T) {
	p, key := accountFixture(t)
	_, proof := recoveryFixture(t, p, key)
	before, e := p.store.Installation(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	c, csrf, g := startRecovery(t, p, proof)
	if w := call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, c, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call(p, "POST", "/api/v1/auth/recovery/abort", struct{}{}, c, csrf); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	after, e := p.store.Installation(context.Background())
	if e != nil || !bytes.Equal(before, after) || p.vault.Unlocked() {
		t.Fatal("abort changed identity", e)
	}
	accountLogin(t, p, accountPassword)
}
func TestAccountRecoveryResetRevalidatesAfterKDF(t *testing.T) {
	for _, boundary := range []string{"cancel", "abort"} {
		t.Run(boundary, func(t *testing.T) {
			p, key := accountFixture(t)
			_, proof := recoveryFixture(t, p, key)
			before, e := p.store.Installation(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			c, csrf, g := startRecovery(t, p, proof)
			if w := call(p, "POST", "/api/v1/auth/recovery/unlock", map[string]string{"grant": g, "dek": crypto.Encode(key)}, c, csrf); w.Code != 200 {
				t.Fatal(w.Code)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			p.beforeAccountPublish = func(*http.Request) { close(entered); <-release }
			raw, _ := json.Marshal(map[string]string{"password": " replacement password ", "password_confirmation": " replacement password "})
			r := httptest.NewRequest("POST", "https://warden.example/api/v1/auth/account/reset", bytes.NewReader(raw))
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
				t.Fatal("reset KDF blocked")
			}
			var abort chan *httptest.ResponseRecorder
			if boundary == "cancel" {
				cancel()
			} else {
				abort = make(chan *httptest.ResponseRecorder, 1)
				go func() { abort <- call(p, "POST", "/api/v1/auth/recovery/abort", struct{}{}, c, csrf) }()
				deadline := time.Now().Add(time.Second)
				for {
					p.mu.Lock()
					phase := p.recoveries[hash(c.Value)].Phase
					p.mu.Unlock()
					if phase == "aborting" {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("abort blocked behind KDF mutex")
					}
					time.Sleep(time.Millisecond)
				}
			}
			close(release)
			select {
			case w := <-done:
				if w.Code == 200 {
					t.Fatal("stale reset committed")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("reset hung")
			}
			if abort != nil {
				select {
				case w := <-abort:
					if w.Code != 200 {
						t.Fatal(w.Code, w.Body)
					}
				case <-time.After(time.Second):
					t.Fatal("abort did not drain")
				}
			}
			after, e := p.store.Installation(context.Background())
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("stale reset changed identity", e)
			}
		})
	}
}
