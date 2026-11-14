package api

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestAPIRedirectPolicyBeforeCredentialSend(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, method := range []string{"GET", "POST"} {
			t.Run(http.StatusText(status)+"/"+method, func(t *testing.T) {
				var reached atomic.Int32
				destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.Write([]byte(`[]`)) }))
				defer destination.Close()
				origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, status) }))
				defer origin.Close()
				injected := origin.Client()
				injected.CheckRedirect = nil
				client := New(origin.URL, injected)
				var err error
				if method == "GET" {
					_, err = client.ListSSH(context.Background())
				} else {
					var result any
					err = client.PostJSON(context.Background(), "/api/v1/client/reports", map[string]string{"summary": "synthetic-private-body"}, &result)
				}
				if reached.Load() != 0 {
					t.Fatal("redirect delivered request/body before rejection")
				}
				if err == nil {
					t.Fatal("redirect accepted")
				}
				if injected.CheckRedirect != nil {
					t.Fatal("mutated injected client")
				}
			})
		}
	}
	var reached atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer plain.Close()
	if _, err := New(plain.URL, nil).ListSSH(context.Background()); err == nil || reached.Load() != 0 {
		t.Fatal("initial HTTP accepted", err)
	}
}
func TestInjectedClientCannotDisableCertificateVerification(t *testing.T) {
	var reached atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.Write([]byte(`[]`)) }))
	defer origin.Close()
	// The injected client deliberately lacks trust and requests an insecure bypass.
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	injected := &http.Client{Transport: transport}
	if _, err := New(origin.URL, injected).ListSSH(context.Background()); err == nil || reached.Load() != 0 {
		t.Fatal("injected client bypassed certificate verification")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("shared injected transport mutated")
	}
}
