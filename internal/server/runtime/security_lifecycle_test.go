package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"warden/internal/client/agent"
	clientssh "warden/internal/client/ssh"
	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/model"
	"warden/internal/server/setup"
	"warden/internal/store"
)

// This client fixture uses the real init/serve/CLI executables, standard signed
// WebAuthn fixtures and a private CA. PRF material is synthetic TEST-ONLY input,
// not evidence of a genuine authenticator or production certificate chain.
type securityInstallation struct {
	configPath, db, origin, ca string
	client                     *http.Client
	initial                    setup.Installation
	dek, root, proof           []byte
	signer                     *ecdsa.PrivateKey
}

func securityBinaries(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS != "linux" {
		t.Skip("Linux controlling-PTY fixture; NativeWindowsSecurity remains required")
	}
	if dir := os.Getenv("WARDEN_ACCEPTANCE_BIN"); dir != "" {
		if !filepath.IsAbs(dir) {
			t.Fatal("acceptance binaries must have an absolute path")
		}
		return dir
	}
	dir := t.TempDir()
	for _, name := range []string{"warden", "warden-server"} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(dir, name), "./cmd/"+name)
		cmd.Dir = "../../.."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", name, err, out)
		}
	}
	return dir
}

func securityFixtureEnvironment() []string {
	// Explicit config paths do not override per-field environment settings.
	// Never let the disposable binaries inherit an operator's live Warden state.
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if !strings.HasPrefix(entry, "WARDEN_") {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func TestSecurityFixtureIgnoresAmbientWardenConfiguration(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Linux controlling-PTY fixture")
	}
	t.Setenv("WARDEN_SERVER_DB_PATH", filepath.Join(t.TempDir(), "ambient.db"))
	t.Setenv("WARDEN_CLIENT_API_BASE_URL", "https://ambient.invalid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := securityInitCommand(ctx, "import os; print(','.join(k for k in os.environ if k.startswith('WARDEN_')))")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.TrimSpace(out)) != 0 {
		t.Fatal("fixture subprocess inherited Warden configuration overrides")
	}
}

func securityInitCommand(ctx context.Context, terminal string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "python3", append([]string{"-c", terminal}, args...)...)
	cmd.Env = securityFixtureEnvironment()
	// Let the PTY owner enter finally and reap init; default CommandContext
	// SIGKILL skips that join. The helper bounds its own child wait to 3s.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

func TestSecurityInitCancellationAllowsTerminalJoin(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Linux controlling-PTY fixture")
	}
	marker := filepath.Join(t.TempDir(), "joined")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := securityInitCommand(ctx, `import pathlib, signal, sys
signal.signal(signal.SIGTERM, lambda *_: (pathlib.Path(sys.argv[1]).write_text('joined'), sys.exit(0)))
print('ready', flush=True)
signal.pause()
`, marker)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready, err := bufio.NewReader(pipe).ReadString('\n')
	cancel()
	waitErr := cmd.Wait()
	if err != nil || ready != "ready\n" || waitErr == nil {
		t.Fatalf("terminal readiness/cancellation: %q %v %v", ready, err, waitErr)
	}
	if _, err = os.Stat(marker); err != nil {
		t.Fatal("cancellation killed terminal before it could join its init child", err)
	}
}

func securityInitialize(t *testing.T, binaries string, methods ...string) *securityInstallation {
	t.Helper()
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	_, port, _ := net.SplitHostPort(address)
	s := &securityInstallation{origin: "https://localhost:" + port, db: filepath.Join(dir, "vault.db"), configPath: filepath.Join(dir, "server.json"), ca: filepath.Join(dir, "ca.pem")}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "tls.key")
	for name, data := range map[string][]byte{s.ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})} {
		if err = os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Setup{PublicOrigin: s.origin, RPID: "localhost", Mode: "tls", TLSCertificate: s.ca, TLSKey: keyPath}
	if len(methods) > 0 {
		cfg.AuthMethod = methods[0]
	}
	raw, err := json.Marshal(map[string]any{"listen_addr": address, "db_path": s.db, "security": cfg})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(s.configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	jar, _ := cookiejar.New(nil)
	s.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, Jar: jar, Timeout: 5 * time.Second}
	t.Cleanup(s.client.CloseIdleConnections)
	// A real controlling terminal, not setup's private password/verifier seams.
	// The password crosses only a private process pipe and is never logged.
	const terminal = `import errno, fcntl, os, pty, re, signal, subprocess, sys, termios
master, slave = pty.openpty()
def controlling():
 os.setsid()
 fcntl.ioctl(0, termios.TIOCSCTTY, 0)
child = subprocess.Popen(sys.argv[1:], stdin=slave, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=controlling)
os.close(slave)
def stop(signum, frame):
 raise SystemExit(1)
signal.signal(signal.SIGTERM, stop)
collected = b''
# Resumable init reprompts existing config. Accept the saved TLS values only
# when each expected field is actually requested, before password disclosure.
prompts = [b'Fresh storage path', b'Public HTTPS origin', b'WebAuthn RP ID', b'Mode (tls or proxy)', b'Listen address', b'TLS certificate path', b'TLS private key path', b'Authentication method (account or passkey)']
answered = 0
try:
 while True:
  try: data = os.read(master, 4096)
  except OSError as error:
   if error.errno == errno.EIO: break
   raise
  if not data: break
  collected += data
  if answered < len(prompts) and prompts[answered] in collected and collected.endswith(b': '):
   os.write(master, b'\n')
   answered += 1
   collected = b''
  match = re.search(rb'Setup password: ([23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8})', collected)
  if match:
   if answered != len(prompts): raise RuntimeError('init skipped saved TLS prompts')
   print(match[1].decode(), flush=True)
   collected = b''
finally:
 os.close(master)
 if child.poll() is None: child.terminate()
 try: code = child.wait(timeout=3)
 except subprocess.TimeoutExpired:
  child.kill()
  code = child.wait()
 sys.exit(code)
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := securityInitCommand(ctx, terminal, filepath.Join(binaries, "warden-server"), "init", "--config", s.configPath)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	joined := false
	defer func() {
		if !joined {
			cancel()
			<-done
		}
	}()
	password, err := bufio.NewReader(pipe).ReadString('\n')
	if err != nil {
		t.Fatal("controlling terminal did not disclose setup password", err)
	}
	csrf := ""
	post := func(route string, body any) []byte {
		t.Helper()
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest("POST", s.origin+"/api/v1/setup/"+route, bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", s.origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		res, err := s.client.Do(req)
		if err != nil {
			t.Fatal(route, err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 200 || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("setup %s: %d", route, res.StatusCode)
		}
		return data
	}
	var authorized struct {
		CSRF string `json:"csrf"`
	}
	if err = json.Unmarshal(post("password", map[string]string{"password": strings.TrimSpace(password)}), &authorized); err != nil {
		t.Fatal(err)
	}
	password = ""
	csrf = authorized.CSRF
	var recovery crypto.Wrapper
	if cfg.AuthenticationMethod() == "account" {
		var b struct {
			Vault string `json:"vault_id"`
		}
		if err = json.Unmarshal(post("account/begin", struct{}{}), &b); err != nil {
			t.Fatal(err)
		}
		s.dek = make([]byte, 32)
		s.root = make([]byte, 32)
		if _, err = rand.Read(s.dek); err != nil {
			t.Fatal(err)
		}
		if _, err = rand.Read(s.root); err != nil {
			t.Fatal(err)
		}
		recovery, err = crypto.Wrap(s.root, s.dek, "recovery", b.Vault, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		salt, _ := crypto.Decode(recovery.KDFSalt, 32)
		s.proof, err = crypto.Derive(s.root, salt, "warden/v1/recovery-auth")
		if err != nil {
			t.Fatal(err)
		}
		verifier := sha256.Sum256(s.proof)
		post("account/prepare", map[string]any{"username": "owner", "password": accountPassword, "password_confirmation": accountPassword, "recovery_wrapper": recovery, "recovery_verifier": crypto.Encode(verifier[:]), "dek": crypto.Encode(s.dek)})
	} else {
		var creation struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
				User      struct {
					ID string `json:"id"`
				} `json:"user"`
			} `json:"publicKey"`
		}
		if err = json.Unmarshal(post("registration/begin", struct{}{}), &creation); err != nil {
			t.Fatal(err)
		}
		owner, err := crypto.Decode(creation.PublicKey.User.ID, 32)
		if err != nil {
			t.Fatal(err)
		}
		registration, signer, id := fixtureRegistration(t, creation.PublicKey.Challenge, s.origin, "localhost", true)
		s.signer = signer
		var registered struct {
			Vault     string `json:"vault_id"`
			Input     string `json:"prf_input"`
			Assertion struct {
				PublicKey struct {
					Challenge string `json:"challenge"`
				} `json:"publicKey"`
			} `json:"assertion"`
		}
		if err = json.Unmarshal(post("registration/finish", json.RawMessage(registration)), &registered); err != nil {
			t.Fatal(err)
		}
		assertion := fixtureAssertion(t, signer, id, owner, registered.Assertion.PublicKey.Challenge, s.origin, "localhost", true)
		post("assertion/finish", json.RawMessage(assertion))
		s.dek = make([]byte, 32)
		s.root = make([]byte, 32)
		if _, err = rand.Read(s.dek); err != nil {
			t.Fatal(err)
		}
		if _, err = rand.Read(s.root); err != nil {
			t.Fatal(err)
		}
		material := bytes.Repeat([]byte{13}, 32) // synthetic PRF, TEST ONLY
		pass, err := crypto.Wrap(material, s.dek, "passkey", registered.Vault, crypto.Encode(id), nil)
		if err != nil {
			t.Fatal(err)
		}
		pass.PRFInput = registered.Input
		recovery, err = crypto.Wrap(s.root, s.dek, "recovery", registered.Vault, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		salt, err := crypto.Decode(recovery.KDFSalt, 32)
		if err != nil {
			t.Fatal(err)
		}
		s.proof, err = crypto.Derive(s.root, salt, "warden/v1/recovery-auth")
		if err != nil {
			t.Fatal(err)
		}
		verifier := sha256.Sum256(s.proof)
		post("prepare", setup.Preparation{Passkey: pass, Recovery: recovery, RecoveryVerifier: crypto.Encode(verifier[:]), DEK: crypto.Encode(s.dek)})
	}
	round, err := recovery.Unwrap(s.root, "recovery", recovery.VaultID, "")
	if err != nil || !bytes.Equal(round, s.dek) {
		t.Fatal("saved recovery roundtrip", err)
	}
	post("finalize", setup.Confirmation{RecoveryAuth: crypto.Encode(s.proof), DEK: crypto.Encode(round)})
	clear(round)
	select {
	case err = <-done:
		joined = true
		if err != nil {
			t.Fatal("init did not exit successfully", err)
		}
	case <-ctx.Done():
		t.Fatal("single-use init did not exit", ctx.Err())
	}
	raw, err = store.ReadInstallation(context.Background(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &s.initial); err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{s.dek, s.root, s.proof} {
		if bytes.Contains(raw, []byte(crypto.Encode(secret))) {
			t.Fatal("raw custody material persisted")
		}
	}
	t.Cleanup(func() { clear(s.dek); clear(s.root); clear(s.proof) })
	return s
}

func securityServe(t *testing.T, binaries string, s *securityInstallation) func() {
	t.Helper()
	s.client.CloseIdleConnections()
	cmd := exec.Command(filepath.Join(binaries, "warden-server"), "serve", "--config", s.configPath)
	cmd.Env = securityFixtureEnvironment()
	// Captures only this disposable process. Do not print secret response bodies.
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		cmd.Process.Signal(os.Interrupt)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve exit: %v", err)
			}
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("serve did not join")
		}
		s.client.CloseIdleConnections()
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, err := s.client.Get(s.origin + "/api/v1/auth/status")
		if err == nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			return stop
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	t.Fatal("production serve not ready")
	return nil
}

// Same approved credential crosses real CLI -> pinned TLS IPC -> HTTPS ->
// durable server restart. Only graph dialing/clock are deterministic substitutes:
// this is pool TTL/auth lifetime proof, NOT remote SSH protocol acceptance.
func securityClientLifecycle(t *testing.T, binaries string, s *securityInstallation, post func(string, any, string) []byte, grantFor func(string, string, string, string) string, restart func()) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "client.json")
	raw, _ := json.Marshal(map[string]string{"api_base_url": s.origin, "ca_certificate": s.ca, "timeout": "3s"})
	if err := os.WriteFile(cfg, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	var pool *agent.Pool
	var stop context.CancelFunc
	var done chan error
	start := func() {
		var err error
		runtime, err := agent.NewRuntimeAt(filepath.Join(dir, "warden/agent"))
		if err != nil {
			t.Fatal(err)
		}
		pool = agent.NewPool(func(context.Context, model.SSHBundle) (*clientssh.Graph, error) { return &clientssh.Graph{}, nil }, func() time.Time { return time.Unix(seconds.Load(), 0) }, 10*time.Minute)
		server, err := agent.NewRuntimeServer(runtime, pool)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stop = cancel
		done = make(chan error, 1)
		go func() { done <- server.Serve(ctx) }()
	}
	halt := func() {
		if stop != nil {
			stop()
			select {
			case err := <-done:
				if err != context.Canceled {
					t.Errorf("agent exit: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("agent did not join")
			}
			stop = nil
		}
	}
	defer halt()
	start()
	cli := func(args ...string) (string, error) {
		select {
		case err := <-done:
			t.Fatalf("owned agent exited before external stop: %v", err)
		default:
		}
		cmd := exec.Command(filepath.Join(binaries, "warden"), append([]string{"--config", cfg, "-n"}, args...)...)
		cmd.Env = append(securityFixtureEnvironment(), "XDG_CACHE_HOME="+dir)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// Wait for discovery, without auto-starting a different daemon via a CLI race.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "warden/agent/credentials-v2.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent discovery not ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	approve := func() string {
		out, err := cli("login")
		if err == nil || !strings.Contains(out, "Web approval required") {
			t.Fatal("unapproved CLI unexpectedly authenticated", err)
		}
		var listed struct {
			Pending []pairing `json:"pending"`
		}
		req, _ := http.NewRequest("GET", s.origin+"/api/v1/auth/clients/list", nil)
		res, err := s.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.NewDecoder(res.Body).Decode(&listed); err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if len(listed.Pending) != 1 || !strings.Contains(out, listed.Pending[0].ID) {
			t.Fatal("pairing commitment did not match CLI")
		}
		p := listed.Pending[0]
		body := fmt.Sprintf(`{"commitment":%q,"id":%q}`, p.Commitment, p.ID)
		post("clients/approve", map[string]string{"id": p.ID, "commitment": p.Commitment}, grantFor("client_approve", "POST", "/api/v1/auth/clients/approve", body))
		time.Sleep(time.Second) // actual server polling rate, not graph idle simulation
		if _, err = cli("login"); err != nil {
			t.Fatal("approved CLI failed", err)
		}
		return p.ID
	}
	approve()
	check := func() {
		t.Helper()
		out, err := cli("config", "search", "tls")
		if err != nil {
			t.Fatal("paired CLI data request failed", err, out)
		}
	}
	check()
	lease, err := pool.Acquire(context.Background(), model.SSHBundle{})
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	seconds.Add(int64((24 * time.Hour) / time.Second))
	pool.Expire()
	if !pool.Empty() {
		t.Fatal("graph did not expire")
	}
	check()
	restart()
	if out, err := cli("status"); err != nil || strings.TrimSpace(out) != "approved" {
		t.Fatal("server restart lost durable authorization", err)
	}
	if out, err := cli("config", "search", "tls"); err == nil || !strings.Contains(out, "vault_locked") {
		t.Fatal("server restart did not lock", err)
	}
	halt()
	start()
	// Actual external stop and a new runtime lose the memory token even while
	// its durable server-side verifier is still approved.
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "warden/agent/credentials-v2.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restarted agent not ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if out, err := cli("status"); err != nil || strings.TrimSpace(out) != "unpaired" {
		t.Fatal("agent restart retained token", err)
	}
	id := approve()
	body := fmt.Sprintf(`{"id":%q}`, id)
	post("clients/revoke", map[string]string{"id": id}, grantFor("client_revoke", "POST", "/api/v1/auth/clients/revoke", body))
	if _, err := cli("config", "search", "tls"); err == nil {
		t.Fatal("revocation did not deny retrieval")
	}
	if out, err := cli("status"); err != nil || strings.TrimSpace(out) != "revoked" {
		t.Fatal("revoked daemon died", err)
	}
	if out, err := cli("logout"); err != nil || strings.TrimSpace(out) != "logged_out" {
		t.Fatal("logout", err)
	}
	if out, err := cli("status"); err != nil || strings.TrimSpace(out) != "unpaired" {
		t.Fatal("logout ended agent", err)
	}
}
