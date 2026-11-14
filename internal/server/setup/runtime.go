package setup

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"time"

	"warden/internal/config"
	"warden/internal/server/auth"
	"warden/internal/store"

	"golang.org/x/term"
)

type Options struct {
	Config       config.Setup
	Bind, DBPath string
	Assets       fs.FS
}
type runtimeDeps struct {
	listen   func(string, string) (net.Listener, error)
	password func() (string, error)
	now      func() time.Time
	verifier ceremonyVerifier
}

// Run requires an already opened controlling terminal, never stdout/stderr.
func Run(ctx context.Context, o Options, terminal *os.File) error {
	if terminal == nil || !term.IsTerminal(int(terminal.Fd())) {
		return errors.New("init requires a controlling terminal; no password will be written to redirected output")
	}
	return run(ctx, o, terminal, runtimeDeps{listen: net.Listen, password: func() (string, error) { return GeneratePassword(rand.Reader) }, now: time.Now})
}
func run(ctx context.Context, o Options, terminal io.Writer, d runtimeDeps) error {
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
	lease, err := store.ReserveInitialization(o.DBPath)
	if err != nil {
		return err
	}
	defer lease.Close()
	verifier := d.verifier
	if verifier == nil {
		verifier, err = auth.NewVerifier(o.Config.PublicOrigin, o.Config.RPID)
		if err != nil {
			return err
		}
	}
	p, err := newPlane(o.Config, o.Assets, verifier, func(ctx context.Context, b []byte) error { return store.CommitInstallation(ctx, o.DBPath, b) })
	if err != nil {
		return err
	}
	defer p.Close()
	listener, err := d.listen("tcp", o.Bind)
	if err != nil {
		return fmt.Errorf("bind setup listener: %w", err)
	}
	defer listener.Close()
	if o.Config.Mode == "tls" {
		listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	}
	readyTime := d.now()
	timer := time.NewTimer(time.Until(readyTime.Add(15 * time.Minute)))
	defer timer.Stop()
	type generatedPassword struct {
		value string
		err   error
	}
	generated := make(chan generatedPassword, 1)
	go func() { value, err := d.password(); generated <- generatedPassword{value, err} }()
	var password string
	select {
	case result := <-generated:
		if result.err != nil {
			return errors.New("generate setup password")
		}
		password = result.value
	case <-timer.C:
		return errors.New("setup deadline expired before password disclosure")
	case <-ctx.Done():
		return ctx.Err()
	}
	if !d.now().Before(readyTime.Add(15 * time.Minute)) {
		return errors.New("setup deadline expired before password disclosure")
	}
	p.now = d.now
	p.ready(readyTime, password)
	server := &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 120 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	// Even a flow-controlled terminal must not extend the ready-time deadline.
	written := make(chan error, 1)
	go func(secret string) {
		_, err := fmt.Fprintf(terminal, "Open %s to initialize Warden. Setup expires in 15 minutes.\nSetup password: %s\n", o.Config.PublicOrigin, secret)
		written <- err
	}(password)
	password = ""
wait:
	for {
		select {
		case err := <-written:
			if err != nil {
				server.Close()
				return errors.New("write controlling terminal")
			}
			written = nil
		case <-p.Done():
			break wait
		case <-ctx.Done():
			server.Close()
			break wait
		case <-timer.C:
			server.Close()
			break wait
		case <-result:
			server.Close()
			return errors.New("setup listener stopped unexpectedly")
		}
	}
	p.Close()
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		server.Close()
	}
	err = <-result
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("setup listener stopped unexpectedly")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !p.initialized.Load() {
		return errors.New("setup ended without initialization; rerun warden-server init with the same fresh storage/config")
	}
	return nil
}
