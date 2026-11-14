package server

import (
	"net/http"
	"testing"
	"time"
)

// Wiring check complements actual TCP/TLS timeout tests in setup/runtime; this
// alone would not establish termination of slow readers/writers.
func TestHTTPServerDefaultBudgets(t *testing.T) {
	s := NewHTTPServer(http.NotFoundHandler())
	if s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != 120*time.Second || s.WriteTimeout != 120*time.Second || s.IdleTimeout != 60*time.Second || !s.DisableGeneralOptionsHandler || s.MaxHeaderBytes != 16<<10 {
		t.Fatal("HTTP request budgets changed", s)
	}
	if s.TLSNextProto != nil || s.Protocols != nil {
		t.Fatal("unexpected protocol activation")
	}
}
