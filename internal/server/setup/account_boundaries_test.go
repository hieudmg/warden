package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
	"warden/internal/crypto"
)

func TestAccountSetupNoncommitBoundaries(t *testing.T) {
	for _, boundary := range []string{"cancel", "expired", "commit-failure"} {
		t.Run(boundary, func(t *testing.T) {
			p, clock := plane(t)
			p.cfg.AuthMethod = "account"
			c, csrf := authorize(t, p)
			dek, root := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
			rw, e := crypto.Wrap(root, dek, "recovery", p.vaultID, "", nil)
			if e != nil {
				t.Fatal(e)
			}
			salt, _ := crypto.Decode(rw.KDFSalt, 32)
			proof, _ := crypto.Derive(root, salt, "warden/v1/recovery-auth")
			b := map[string]any{"username": "owner", "password": " correct password ", "password_confirmation": " correct password ", "recovery_wrapper": rw, "recovery_verifier": hashToken(proof), "dek": crypto.Encode(dek)}
			committed := false
			p.commit = func(context.Context, []byte) error {
				if boundary == "commit-failure" {
					return errors.New("injected storage failure")
				}
				committed = true
				return nil
			}
			if boundary == "cancel" {
				raw, _ := json.Marshal(b)
				r := httptest.NewRequest("POST", "https://warden.example/api/v1/setup/account/prepare", bytes.NewReader(raw))
				r.Header.Set("Origin", p.cfg.PublicOrigin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Cookie", c)
				r.Header.Set("X-CSRF-Token", csrf)
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
				w := httptest.NewRecorder()
				p.ServeHTTP(w, r)
				if w.Code == 200 {
					t.Fatal("canceled preparation published")
				}
			} else {
				if w := request(p, "/api/v1/setup/account/prepare", b, c, csrf); w.Code != 200 {
					t.Fatal(w.Code, w.Body)
				}
				if boundary == "expired" {
					*clock = clock.Add(16 * time.Minute)
				}
				if w := request(p, "/api/v1/setup/finalize", Confirmation{RecoveryAuth: crypto.Encode(proof), DEK: crypto.Encode(dek)}, c, csrf); w.Code == 200 {
					t.Fatal("unexpected commit")
				}
			}
			if committed || p.initialized.Load() {
				t.Fatal("failed setup initialized")
			}
		})
	}
}
func TestAccountSetupAdmissionBeforeBodyRead(t *testing.T) {
	p, _ := plane(t)
	p.cfg.AuthMethod = "account"
	c, csrf := authorize(t, p)
	for n := 0; n < cap(p.accountOperations); n++ {
		p.accountOperations <- struct{}{}
	}
	r := httptest.NewRequest("POST", "https://warden.example/api/v1/setup/account/prepare", nil)
	r.Header.Set("Origin", p.cfg.PublicOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Cookie", c)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Body = &accountPanicBody{}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal("admission not enforced", w.Code)
	}
}

type accountPanicBody struct{}

func (*accountPanicBody) Read([]byte) (int, error) { panic("body read before crypto admission") }
func (*accountPanicBody) Close() error             { return nil }
