package runtime

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
	"warden/internal/crypto"
)

func TestRecoveryActivationDoesNotExpireWhileDrainingOldLease(t *testing.T) {
	p, _, _, key, _ := runtimeFixture(t)
	_, proof := recoveryFixture(t, p, key)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	ctx, release, err := p.vault.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	begin := call(p, "POST", "/api/v1/auth/recovery/begin", struct{}{}, nil, "")
	var b struct {
		ID string `json:"id"`
	}
	json.Unmarshal(begin.Body.Bytes(), &b)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- call(p, "POST", "/api/v1/auth/recovery/proof", map[string]string{"id": b.ID, "proof": crypto.Encode(proof)}, nil, "")
	}()
	waitDelivery(t, ctx.Done(), "proof cancels old lease")
	statusDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { statusDone <- call(p, "GET", "/api/v1/auth/status", nil, browser, csrf) }()
	select {
	case w := <-statusDone:
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("activating recovery mistaken for expired context; status blocked on second Lock")
	}
	release()
	select {
	case result := <-done:
		if result.Code != 200 {
			t.Fatal(result.Code, result.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("proof did not finish")
	}
	p.mu.Lock()
	s, ok := p.recoveries[p.recoveryRun]
	p.mu.Unlock()
	if !ok || s.Phase != "proof" {
		t.Fatal("recovery reservation lost")
	}
}
