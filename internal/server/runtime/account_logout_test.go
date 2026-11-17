package runtime

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogoutSerializesWithCredentialPublication(t *testing.T) {
	p, _ := accountFixture(t)
	c, csrf := accountLogin(t, p, accountPassword)
	r := httptest.NewRequest("POST", "https://warden.example/api/v1/auth/logout", strings.NewReader(`{}`))
	r.AddCookie(c)
	r.Header.Set("X-CSRF-Token", csrf)
	x, ok := p.session(r)
	if !ok {
		t.Fatal("fixture session")
	}
	p.mu.Lock()
	held := true
	defer func() {
		if held {
			p.mu.Unlock()
		}
	}()
	done := make(chan struct{})
	w := httptest.NewRecorder()
	go func() { p.authHTTP(w, r, x); close(done) }()
	select {
	case <-done:
		t.Fatal("logout revoked during serialized credential publication")
	case <-time.After(25 * time.Millisecond):
	}
	if _, e := p.store.Session(context.Background(), x.Hash); e != nil {
		t.Fatal("session revoked before publication mutex released")
	}
	p.mu.Unlock()
	held = false
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("logout hung")
	}
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if _, e := p.store.Session(context.Background(), x.Hash); e == nil {
		t.Fatal("logout did not revoke")
	}
}
