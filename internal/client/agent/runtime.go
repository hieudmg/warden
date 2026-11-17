package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
)

const (
	runtimeDirectory = "warden/agent"
	runtimeEndpoint  = "agent.sock"
	runtimeToken     = "token"
)

// Runtime owns the per-user endpoint and its authentication token. The
// platform-specific files provide the local listener and dialer; all state
// files are managed here so Unix and Windows startup use the same lifecycle.
type Runtime struct {
	mu sync.Mutex

	dir       string
	endpoint  string
	tokenFile string
	listener  net.Listener
}

// NewRuntime returns a runtime rooted at os.UserCacheDir()/warden/agent.
// Files are created lazily by Listen or CreateToken.
func NewRuntime() (*Runtime, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("resolve agent cache directory: %w", err)
	}
	return NewRuntimeAt(filepath.Join(cache, runtimeDirectory))
}

// NewRuntimeAt returns a runtime rooted at dir. It is useful to tests and to
// callers that need an explicitly selected private cache root; dir itself is
// still created and protected by Runtime before state is written.
func NewRuntimeAt(dir string) (*Runtime, error) {
	if dir == "" {
		return nil, errors.New("agent runtime directory is empty")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve agent runtime directory: %w", err)
	}
	return &Runtime{
		dir:       absolute,
		tokenFile: filepath.Join(absolute, runtimeToken),
	}, nil
}

// Listen creates (or reuses) the authenticated local endpoint. If a token
// already exists it is validated rather than replaced, which lets concurrent
// starters race safely while only one listener wins the endpoint creation.
func (r *Runtime) Listen() (net.Listener, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.initPathsLocked(); err != nil {
		return nil, err
	}
	if r.listener != nil {
		return r.listener, nil
	}
	if err := ensurePrivateDirectory(r.dir); err != nil {
		return nil, err
	}
	if err := r.ensureTokenLocked(); err != nil {
		return nil, err
	}

	listener, err := listenRuntime(r, r.endpoint)
	if err != nil {
		return nil, err
	}
	r.listener = listener
	return listener, nil
}

// Dial connects to this runtime's local endpoint using ctx for cancellation.
func (r *Runtime) Dial(ctx context.Context) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("agent dial context is nil")
	}
	r.mu.Lock()
	if err := r.initPathsLocked(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	endpoint := r.endpoint
	r.mu.Unlock()
	return dialRuntime(ctx, endpoint)
}

// ReadToken reads and validates the current runtime token. The returned slice
// is independent of the file buffer and may be retained by a caller.
func (r *Runtime) ReadToken() ([]byte, error) {
	r.mu.Lock()
	if err := r.initPathsLocked(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	path := r.tokenFile
	r.mu.Unlock()
	return readTokenFile(path)
}

// CreateToken atomically creates a fresh 256-bit token with mode 0600. It
// never replaces an existing token; callers racing to start an agent can use
// the existing token after receiving os.ErrExist.
func (r *Runtime) CreateToken() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.initPathsLocked(); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(r.dir); err != nil {
		return nil, err
	}

	return r.createTokenLocked()
}

// Cleanup closes this runtime's listener and removes only this runtime's
// endpoint and token files. It is safe to call repeatedly.
func (r *Runtime) Cleanup() error {
	r.mu.Lock()
	if err := r.initPathsLocked(); err != nil {
		r.mu.Unlock()
		return err
	}
	listener := r.listener
	r.listener = nil
	endpoint, token := r.endpoint, r.tokenFile
	r.mu.Unlock()

	var errs []error
	if listener != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if err := cleanupRuntimeEndpoint(endpoint); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if err := removeTokenFile(token); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// EndpointPath returns the local endpoint path. The path is an implementation
// detail for diagnostics and tests; callers should normally use Dial.
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
			return fmt.Errorf("resolve agent cache directory: %w", err)
		}
		r.dir = filepath.Join(cache, runtimeDirectory)
	}
	absolute, err := filepath.Abs(r.dir)
	if err != nil {
		return fmt.Errorf("resolve agent runtime directory: %w", err)
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

func (r *Runtime) ensureTokenLocked() error {
	if _, err := readTokenFile(r.tokenFile); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := r.createTokenLocked(); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		_, err = readTokenFile(r.tokenFile)
		return err
	}
	return nil
}

func (r *Runtime) createTokenLocked() ([]byte, error) {
	file, err := os.OpenFile(r.tokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	token := make([]byte, TokenBytes)
	if _, err := rand.Read(token); err != nil {
		_ = os.Remove(r.tokenFile)
		return nil, fmt.Errorf("generate agent token: %w", err)
	}
	if err := writeAll(file, token); err != nil {
		_ = os.Remove(r.tokenFile)
		return nil, fmt.Errorf("write agent token: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = os.Remove(r.tokenFile)
		return nil, fmt.Errorf("protect agent token: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = os.Remove(r.tokenFile)
		return nil, fmt.Errorf("sync agent token: %w", err)
	}
	return token, nil
}

func readTokenFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("agent token is not a regular file")
	}
	if err := validateTokenFileInfo(info); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	token := make([]byte, TokenBytes)
	if _, err := io.ReadFull(file, token); err != nil {
		return nil, fmt.Errorf("read agent token: %w", err)
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read agent token: %w", err)
	} else if n != 0 {
		return nil, errors.New("agent token has invalid length")
	}
	return token, nil
}

func removeTokenFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("agent token is not a regular file")
	}
	return os.Remove(path)
}

// dirPath is kept unexported for package-local Unix permission tests.
func (r *Runtime) dirPath() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.initPathsLocked() != nil {
		return ""
	}
	return r.dir
}

// endpointPath and tokenPath are package-local aliases used by tests and
// future same-package agent components.
func (r *Runtime) endpointPath() string { return r.EndpointPath() }
func (r *Runtime) tokenPath() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.initPathsLocked() != nil {
		return ""
	}
	return r.tokenFile
}
