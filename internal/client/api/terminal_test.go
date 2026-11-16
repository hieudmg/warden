package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestAPIErrorTerminalControlsEscaped(t *testing.T) {
	for _, text := range []string{
		"héllo 世界\x1b]52;c;payload\a\x00\x08\t\r\n\x7f\u0085\u009b",
		strings.Repeat("界", 400),
		strings.Repeat("\x1b", 1024),
		strings.Repeat("x", 1023) + "界",
	} {
		t.Run("message", func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"code": "validation", "message": text})
			}))
			defer srv.Close()
			_, err := New(srv.URL, srv.Client()).ListSSH(context.Background())
			var ae *APIError
			if !errors.As(err, &ae) || ae.Code != "validation" || ae.StatusCode != 400 {
				t.Fatalf("classification lost: %v", err)
			}
			if len(ae.Message) > 1024 || !utf8.ValidString(ae.Message) {
				t.Fatalf("message byte bound split UTF-8: %d", len(ae.Message))
			}
			for _, value := range []string{err.Error()} {
				if len(value) > 1024 || !utf8.ValidString(value) {
					t.Fatalf("not bounded valid UTF-8: bytes=%d", len(value))
				}
				for _, r := range value {
					if unicode.IsControl(r) {
						t.Fatalf("raw terminal control %U in %q", r, value)
					}
				}
			}
			if strings.HasPrefix(text, "héllo") && !strings.Contains(err.Error(), `héllo 世界\x1b]52;c;payload\u0007\u0000\u0008\t\r\n\u007f\u0085\u009b`) {
				t.Fatalf("unsafe or mangled message: %q", err.Error())
			}
		})
	}
	// Code is server-controlled too, not just Message. Direct errors must also
	// be safe when formatted outside the CLI, without losing typed fields.
	ae := &APIError{StatusCode: 400, Code: "bad\x1b[2J\r\n\u009b", Message: "ok\xff世界"}
	// Formatting is a presentation boundary, not a mutation of structured
	// fields or error identity. JSON keeps its normal format escaping.
	originalCode, originalMessage := ae.Code, ae.Message
	rendered := ae.Error()
	if ae.Code != originalCode || ae.Message != originalMessage {
		t.Fatal("render mutated structured error")
	}
	if !utf8.ValidString(rendered) || strings.ContainsAny(rendered, "\x1b\r\n\u009b") || !strings.Contains(rendered, "世界") {
		t.Fatalf("unsafe error: %q", rendered)
	}
	longCode := &APIError{StatusCode: 400, Code: strings.Repeat("\x1b", 2048), Message: "ok"}
	if text := longCode.Error(); len(text) > 1024 || strings.ContainsRune(text, '\x1b') || !utf8.ValidString(text) {
		t.Fatal("unbounded/unsafe error code")
	}
	structured := &APIError{StatusCode: 400, Code: "validation", Message: "héllo世界\x1b\r\n\u009b"}
	encoded, err := json.Marshal(structured)
	if err != nil || strings.ContainsAny(string(encoded), "\x1b\r\n") {
		t.Fatalf("invalid JSON format escaping: %q, %v", encoded, err)
	}
	var decoded APIError
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != *structured {
		t.Fatal("structured JSON meaning changed", err)
	}
}
