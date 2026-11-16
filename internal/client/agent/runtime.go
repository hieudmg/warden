package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
)

const (
	runtimeDirectory   = "warden/agent"
	runtimeEndpoint    = "agent.sock"
	runtimeToken       = "credentials-v2.json"
	runtimeLock        = "runtime.lock"
	maxCredentialBytes = 16 * 1024
)

type runtimeCredentials struct {
	Version     uint8  `json:"version"`
	Token       []byte `json:"token"`
	Certificate []byte `json:"certificate"`
}

// Runtime owns an endpoint, a lifetime OS lock, and one ephemeral TLS identity.
// Only the separate IPC token and public certificate are ever written to disk.
// The credential file is the trust boundary: native permissions must hold.
// Same-user/administrator compromise is outside this boundary.
type Runtime struct {
	mu                       sync.Mutex
	dir, endpoint, tokenFile string
	listener                 net.Listener
	directory                *privateDirectory
	lock                     *os.File
	credentials              runtimeCredentials
}

type privateDirectory struct {
	root *os.Root
	file *os.File
}

func (d *privateDirectory) Close() { _ = d.file.Close(); _ = d.root.Close() }

func NewRuntime() (*Runtime, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("resolve agent cache directory: %w", err)
	}
	return NewRuntimeAt(filepath.Join(cache, runtimeDirectory))
}
func NewRuntimeAt(dir string) (*Runtime, error) {
	if dir == "" {
		return nil, errors.New("agent runtime directory is empty")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &Runtime{dir: absolute, tokenFile: filepath.Join(absolute, runtimeToken)}, nil
}

// Listen binds BEFORE publishing trust material. The OS lock serializes starts
// and survives no crash; credential publication is exclusive and atomic. A
// losing starter owns nothing and cannot clean up the winning runtime.
func (r *Runtime) Listen() (net.Listener, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.initPathsLocked(); err != nil {
		return nil, err
	}
	if r.listener != nil {
		return r.listener, nil
	}
	directory, err := openPrivateDirectory(r.dir, true)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			directory.Close()
		}
	}()
	lock, err := openPrivateChild(directory.file, runtimeLock, os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			_ = lock.Close()
		}
	}()
	if err := lockRuntime(lock); err != nil {
		return nil, fmt.Errorf("agent runtime already owned or lock unavailable: %w", err)
	}
	// Validate stale state before binding, and never replace symlinks, broad
	// permissions, malformed records, or unknown formats to make startup work.
	old, err := readCredentials(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("agent discovery refused; stop old agent and inspect private runtime: %w", err)
	}
	certificate, err := newAgentIdentity()
	if err != nil {
		return nil, err
	}
	token := make([]byte, TokenBytes)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	raw, err := listenRuntime(r, r.endpoint)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	// Owning the lock AND listener proves prior credentials stale. Inconclusive
	// endpoint probes never reach here. Removal stays inside the anchored root.
	if old != nil {
		if err := directory.root.Remove(runtimeToken); err != nil {
			return nil, err
		}
	}
	credentials := runtimeCredentials{Version: Version, Token: token, Certificate: certificate.Certificate[0]}
	if err := publishCredentials(directory, credentials); err != nil {
		return nil, err
	}
	r.directory = directory
	r.lock = lock
	r.credentials = credentials
	r.listener = tls.NewListener(raw, agentServerTLS(certificate))
	success = true
	return r.listener, nil
}

// Dial authenticates the exact current runtime certificate before returning a
// connection. No caller can accidentally use a raw Runtime dial for payloads.
func (r *Runtime) Dial(ctx context.Context) (net.Conn, error) {
	conn, _, err := r.connect(ctx)
	return conn, err
}
func (r *Runtime) connect(ctx context.Context) (net.Conn, []byte, error) {
	if ctx == nil {
		return nil, nil, errors.New("agent dial context is nil")
	}
	r.mu.Lock()
	err := r.initPathsLocked()
	dir, endpoint := r.dir, r.endpoint
	r.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	directory, err := openPrivateDirectory(dir, false)
	if err != nil {
		return nil, nil, err
	}
	defer directory.Close()
	credentials, err := readCredentials(directory)
	if err != nil {
		return nil, nil, err
	}
	// Dial as well as handshake is bounded even for background callers.
	dialCtx, cancel := context.WithTimeout(ctx, agentHandshakeTimeout)
	defer cancel()
	raw, err := dialRuntime(dialCtx, endpoint)
	if err != nil {
		return nil, nil, err
	}
	conn, err := authenticateAgent(dialCtx, raw, credentials.Certificate)
	if err != nil {
		return nil, nil, err
	}
	return conn, credentials.Token, nil
}
func (r *Runtime) ReadToken() ([]byte, error) {
	r.mu.Lock()
	err := r.initPathsLocked()
	dir := r.dir
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	directory, err := openPrivateDirectory(dir, false)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	credentials, err := readCredentials(directory)
	if err != nil {
		return nil, err
	}
	return credentials.Token, nil
}

func readCredentials(directory *privateDirectory) (*runtimeCredentials, error) {
	file, err := openPrivateChild(directory.file, runtimeToken, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCredentialBytes {
		return nil, errors.New("agent credential file too large")
	}
	var credentials runtimeCredentials
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return nil, errors.New("invalid agent credential file; stop old agent and inspect runtime")
	}
	if decoder.Decode(new(any)) != io.EOF || credentials.Version != Version || len(credentials.Token) != TokenBytes {
		return nil, errors.New("incompatible agent credentials; stop old agent and inspect runtime")
	}
	certificate, err := x509.ParseCertificate(credentials.Certificate)
	if err != nil {
		return nil, errors.New("invalid agent trust certificate")
	}
	if err := certificate.VerifyHostname(agentTLSName); err != nil {
		return nil, errors.New("invalid agent trust name")
	}
	return &credentials, nil
}

// Pass-through seam for deterministic staging-unlink failures in startup tests.
var removeCredentialStage = func(directory *privateDirectory, name string) error {
	return directory.root.Remove(name)
}

func publishCredentials(directory *privateDirectory, credentials runtimeCredentials) error {
	data, err := json.Marshal(credentials)
	if err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	name := ".credentials-" + hex.EncodeToString(random[:])
	file, err := openPrivateChild(directory.file, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		// Before publication only an untrusted staging name exists. After the
		// link succeeds, never retry/repair ambiguous state on a failed unlink.
		if !published {
			_ = removeCredentialStage(directory, name)
		}
	}()
	if err := writeAll(file, data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Hard-link publication refuses replacement and readers never see partial JSON.
	if err := directory.root.Link(name, runtimeToken); err != nil {
		return err
	}
	published = true
	// Until this succeeds, readers correctly refuse the two-link record.
	if err := removeCredentialStage(directory, name); err != nil {
		return fmt.Errorf("remove agent credential staging entry: %w", err)
	}
	return nil
}

// Cleanup only removes files when this Runtime acquired the lifetime lock and
// published its own listener. A client/failed contender must never unlink them.
func (r *Runtime) Cleanup() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lock == nil {
		return nil
	}
	var errs []error
	if r.listener != nil {
		if err := r.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	// The lock excludes other runtimes through unlink and listener close.
	if err := r.directory.root.Remove(runtimeToken); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	r.listener = nil
	r.credentials = runtimeCredentials{}
	_ = r.lock.Close()
	r.lock = nil
	r.directory.Close()
	r.directory = nil
	return errors.Join(errs...)
}
func (r *Runtime) EndpointPath() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.initPathsLocked() != nil {
		return ""
	}
	return r.endpoint
}
func (r *Runtime) initPathsLocked() error {
	if r.dir == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return err
		}
		r.dir = filepath.Join(cache, runtimeDirectory)
	}
	absolute, err := filepath.Abs(r.dir)
	if err != nil {
		return err
	}
	r.dir = absolute
	if r.endpoint == "" {
		r.endpoint = runtimeEndpointPath(r.dir)
	}
	if r.tokenFile == "" {
		r.tokenFile = filepath.Join(r.dir, runtimeToken)
	}
	return nil
}
func (r *Runtime) dirPath() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.initPathsLocked()
	return r.dir
}
func (r *Runtime) endpointPath() string { return r.EndpointPath() }
func (r *Runtime) tokenPath() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.initPathsLocked()
	return r.tokenFile
}
