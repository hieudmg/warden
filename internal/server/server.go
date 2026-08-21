package server

import (
	"context"
	"net"
	"net/http"
)

// Server wraps an http.Server with the warden-server middleware (identity
// header and panic recovery) and graceful shutdown. The API and web UI
// share one listener; route registration happens on the handler passed to
// New.
type Server struct {
	httpServer *http.Server
	handler    http.Handler
}

// New returns a Server serving handler on addr. The middleware-wrapped
// handler is available via Handler for direct use in tests.
func New(addr string, handler http.Handler) *Server {
	return &Server{
		handler:    withMiddleware(handler),
		httpServer: &http.Server{Addr: addr},
	}
}

// Handler returns the middleware-wrapped handler.
func (s *Server) Handler() http.Handler { return s.handler }

// ListenAndServe serves on the configured address.
func (s *Server) ListenAndServe() error {
	s.httpServer.Handler = s.handler
	return s.httpServer.ListenAndServe()
}

// Serve serves on an existing listener (used by tests and custom listeners).
func (s *Server) Serve(l net.Listener) error {
	s.httpServer.Handler = s.handler
	return s.httpServer.Serve(l)
}

// Shutdown gracefully shuts down the server, waiting for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// withMiddleware sets the Server identity header and converts panics into
// stable 500 responses. It never logs request bodies.
func withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "warden-server")
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				if !sw.wroteHeader {
					WriteError(sw, http.StatusInternalServerError, ErrInternal, "internal server error")
				}
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
