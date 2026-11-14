package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"time"

	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/server"
	"warden/internal/server/audit"
	"warden/internal/server/auth"
	"warden/internal/server/profiles"
	"warden/internal/server/reports"
	"warden/internal/store"
)

type Options struct {
	Config       config.Setup
	Bind, DBPath string
	Assets       fs.FS
}

// Run always uses the real pinned verifier and starts with a new, locked vault.
// No config, environment or HTTP request can inject a verifier or restore a key.
func Run(ctx context.Context, o Options) error {
	if err := o.Config.Validate(o.Bind); err != nil {
		return err
	}
	var certificate tls.Certificate
	var err error
	if o.Config.Mode == "tls" {
		certificate, err = tls.LoadX509KeyPair(o.Config.TLSCertificate, o.Config.TLSKey)
		if err != nil {
			return errors.New("load configured TLS certificate/key")
		}
	}
	vault := crypto.NewVault()
	var installationRecord []byte
	s, err := store.OpenInitialized(ctx, o.DBPath, func(raw []byte) error {
		_, err := validateInstallation(raw, o.Config)
		if err == nil {
			installationRecord = append([]byte(nil), raw...)
		}
		return err
	}, vault)
	if err != nil {
		return err
	}
	defer s.Close()
	defer vault.Lock()
	install, err := validateInstallation(installationRecord, o.Config)
	if err != nil {
		return err
	}
	verifier, err := auth.NewVerifier(o.Config.PublicOrigin, o.Config.RPID)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	recorder := audit.New(s)
	profiles.New(s, recorder).Register(mux)
	reports.New(s, recorder).Register(mux)
	// A normal ServeMux 404, not an SPA fallback, owns unknown API routes.
	handler, err := newPlane(o.Config, s, install, vault, verifier, server.ServeUI(mux, o.Assets))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", o.Bind)
	if err != nil {
		return err
	}
	defer listener.Close()
	if o.Config.Mode == "tls" {
		listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	}
	httpServer := &http.Server{DisableGeneralOptionsHandler: true, Handler: server.New(o.Bind, handler).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 120 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	defer httpServer.Close()
	result := make(chan error, 1)
	go func() { result <- httpServer.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		// Closing connections cancels response delivery before draining key access.
		httpServer.Close()
		vault.Lock()
		<-result
		return ctx.Err()
	}
}
