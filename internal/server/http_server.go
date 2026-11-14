package server

import (
	"net/http"
	"time"
)

// NewHTTPServer applies the same bounded HTTP/1 request budgets to setup and
// runtime. Callers own listeners (including TLS); this does not enable HTTP/2.
// Tests may shorten the returned standard server's budgets before Serve.
func NewHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:                      handler,
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            5 * time.Second,
		ReadTimeout:                  120 * time.Second,
		WriteTimeout:                 120 * time.Second,
		IdleTimeout:                  60 * time.Second,
		MaxHeaderBytes:               16 << 10,
	}
}
