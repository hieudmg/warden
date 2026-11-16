package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServerHeader(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := New("", handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	srv.Handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("Server"); got != "warden-server" {
		t.Errorf("Server header = %q, want warden-server", got)
	}
}

func TestPanicRecovery(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	srv := New("", handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestResponseControllerFlushPreservesPanicStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	handler := New("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatal(err)
		}
		panic("after flush")
	})).Handler()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if !rec.Flushed || rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("flushed panic appended an error response: %d %q", rec.Code, rec.Body)
	}
}

func TestMiddlewarePropagatesAbortHandler(t *testing.T) {
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Errorf("panic = %v, want ErrAbortHandler", got)
		}
	}()
	New("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})).Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

func TestGracefulShutdown(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	srv := New("", handler)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + l.Addr().String() + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-done; err != nil && err != http.ErrServerClosed {
		t.Fatalf("serve returned %v, want ErrServerClosed", err)
	}
}
