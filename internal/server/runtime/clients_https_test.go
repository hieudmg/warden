package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"testing"
	"time"

	"warden/internal/client/api"
	clientreport "warden/internal/client/report"
	"warden/internal/config"
	"warden/internal/crypto"
	"warden/internal/model"
	"warden/internal/store"
)

func TestT4ClientCapabilitiesHelper(t *testing.T) {
	path := os.Getenv("WARDEN_T4_CLIENT_FIXTURE")
	if path == "" {
		return
	}
	cfg, err := config.LoadClient(config.ClientOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	c := api.NewAgent(cfg.APIBaseURL, cfg.CACertificate, cfg.Timeout)
	ctx := context.Background()
	ssh, err := c.ListSSH(ctx)
	if err != nil || len(ssh) != 1 {
		t.Fatal("SSH list", err)
	}
	if _, err = c.GetSSH(ctx, ssh[0].ID); err != nil {
		t.Fatal(err)
	}
	b, err := c.GetSSHBundle(ctx, ssh[0].ID)
	if err != nil || string(b.Target.Password) != "synthetic-remote-password" {
		t.Fatal("SSH transport", err)
	}
	if _, err = c.SSHDependents(ctx, ssh[0].ID); err != nil {
		t.Fatal(err)
	}
	db, err := c.ListDB(ctx)
	if err != nil || len(db) != 1 {
		t.Fatal("DB list", err)
	}
	if _, err = c.GetDB(ctx, db[0].ID); err != nil {
		t.Fatal(err)
	}
	d, err := c.GetDBBundle(ctx, db[0].ID)
	if err != nil || string(d.Password) != "synthetic-db-password" {
		t.Fatal("DB transport", err)
	}
	if _, err = c.DBDependents(ctx, db[0].ID); err != nil {
		t.Fatal(err)
	}
	if err = c.SetDBArchived(ctx, db[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if err = c.SetDBArchived(ctx, db[0].ID, false); err != nil {
		t.Fatal(err)
	}
	if err = c.SetSSHArchived(ctx, ssh[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if err = c.SetSSHArchived(ctx, ssh[0].ID, false); err != nil {
		t.Fatal(err)
	}
	reports := clientreport.New(c)
	if _, err = reports.CreateProject(ctx, "fixture-project"); err != nil {
		t.Fatal(err)
	}
	if _, err = reports.ListProjects(ctx); err != nil {
		t.Fatal(err)
	}
	existing, err := reports.ListReports(ctx, "fixture-project")
	if err != nil {
		t.Fatal(err)
	}
	// Real validated reports allow 16 KiB summaries. Eighty records force the
	// actual HTTPS/API/IPC response past one frame without raising its 1 MiB cap.
	for i := len(existing); i < 80; i++ {
		if _, err = reports.CreateReport(ctx, model.ReportRequest{Project: "fixture-project", Title: "fixture", Summary: strings.Repeat("x", 16<<10), AgentModel: "standards-fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	existing, err = reports.ListReports(ctx, "fixture-project")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(existing)
	if err != nil || len(encoded) <= 1<<20 {
		t.Fatal("representative report response did not cross original frame limit", err, len(encoded))
	}
}

// Actual CLI binaries, two distinct same-user agent runtimes, production server
// subprocess and real signed WebAuthn fixtures. No real DB/remote DB/authenticator.
func TestHTTPSClientEnrollmentTwoDevicesRestartAndRevoke(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("native Windows execution pending; this subprocess harness uses POSIX signals/cache")
	}
	initialPlane, _, initial, dek, signer := runtimeFixture(t)
	_ = initialPlane
	dir := t.TempDir()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	reserved.Close()
	_, port, _ := net.SplitHostPort(address)
	origin := "https://localhost:" + port
	initial.PublicOrigin = origin
	initial.RPID = "localhost"
	raw, _ := json.Marshal(initial)
	db := filepath.Join(dir, "vault.db")
	if err = store.CommitInstallation(context.Background(), db, raw); err != nil {
		t.Fatal(err)
	}
	signingTLS, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &signingTLS.PublicKey, signingTLS)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(signingTLS)
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "tls.key")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	roots := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	roots.AddCert(parsed)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, Jar: jar, Timeout: 3 * time.Second}
	defer hc.CloseIdleConnections()
	opts := Options{Config: config.Setup{PublicOrigin: origin, RPID: "localhost", Mode: "tls", TLSCertificate: certPath, TLSKey: keyPath}, Bind: address, DBPath: db}
	optsPath := filepath.Join(dir, "server.json")
	encoded, _ := json.Marshal(opts)
	os.WriteFile(optsPath, encoded, 0600)
	var serverProcess *exec.Cmd
	stop := func(p **exec.Cmd) {
		t.Helper()
		if *p == nil {
			return
		}
		(*p).Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func(c *exec.Cmd) { done <- c.Wait() }(*p)
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("subprocess failed", err)
			}
		case <-time.After(5 * time.Second):
			(*p).Process.Kill()
			<-done
			t.Fatal("subprocess did not stop")
		}
		*p = nil
	}
	startServer := func() {
		t.Helper()
		serverProcess = exec.Command(os.Args[0], "-test.run=^TestRuntimeSubprocessHelper$", "-test.count=1")
		serverProcess.Env = append(os.Environ(), "WARDEN_T2_TEST_CONFIG="+optsPath)
		if err = serverProcess.Start(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			res, e := hc.Get(origin + "/api/v1/auth/status")
			if e == nil {
				res.Body.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("server readiness failed")
	}
	defer stop(&serverProcess)
	startServer()
	csrf := ""
	request := func(method, path string, body any, grant string) (int, []byte) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, origin+path, bytes.NewReader(raw))
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("X-Warden-Action", grant)
		res, e := hc.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		data, e := io.ReadAll(res.Body)
		if e != nil {
			t.Fatal(e)
		}
		return res.StatusCode, data
	}
	post := func(path string, body any, grant string) []byte {
		t.Helper()
		code, data := request("POST", "/api/v1/auth/"+path, body, grant)
		if code != 200 {
			t.Fatalf("%s: %d %s", path, code, data)
		}
		return data
	}
	signedFinish := func(begin []byte, finish string) {
		t.Helper()
		var b struct {
			ID      string `json:"id"`
			Options struct {
				PublicKey struct {
					Challenge string `json:"challenge"`
				} `json:"publicKey"`
			} `json:"options"`
		}
		json.Unmarshal(begin, &b)
		assertion := fixtureAssertion(t, signer, initial.Owner.Credentials[0].ID, initial.Owner.ID, b.Options.PublicKey.Challenge, origin, "localhost", true)
		data := post(finish, map[string]any{"id": b.ID, "credential": json.RawMessage(assertion)}, "")
		var result struct {
			CSRF string `json:"csrf"`
		}
		json.Unmarshal(data, &result)
		if result.CSRF != "" {
			csrf = result.CSRF
		}
	}
	signedFinish(post("login/begin", struct{}{}, ""), "login/finish")
	grantFor := func(action, target string, body any) string {
		t.Helper()
		raw, _ := json.Marshal(body)
		begin := post("fresh/begin", map[string]string{"action": action, "credential_id": crypto.Encode(initial.Owner.Credentials[0].ID), "method": "POST", "path": target, "digest": hash(string(raw))}, "")
		var b struct {
			ID      string `json:"id"`
			Options struct {
				PublicKey struct {
					Challenge string `json:"challenge"`
				} `json:"publicKey"`
			} `json:"options"`
		}
		json.Unmarshal(begin, &b)
		signed := fixtureAssertion(t, signer, initial.Owner.Credentials[0].ID, initial.Owner.ID, b.Options.PublicKey.Challenge, origin, "localhost", true)
		data := post("fresh/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, "")
		var result struct {
			Grant string `json:"grant"`
		}
		json.Unmarshal(data, &result)
		return result.Grant
	}
	unlock := func() {
		t.Helper()
		begin := post("fresh/begin", map[string]string{"action": "unlock", "credential_id": crypto.Encode(initial.Owner.Credentials[0].ID)}, "")
		var b struct {
			ID      string `json:"id"`
			Options struct {
				PublicKey struct {
					Challenge string `json:"challenge"`
				} `json:"publicKey"`
			} `json:"options"`
		}
		json.Unmarshal(begin, &b)
		signed := fixtureAssertion(t, signer, initial.Owner.Credentials[0].ID, initial.Owner.ID, b.Options.PublicKey.Challenge, origin, "localhost", true)
		data := post("fresh/finish", map[string]any{"id": b.ID, "credential": json.RawMessage(signed)}, "")
		var g struct {
			Grant string `json:"grant"`
		}
		json.Unmarshal(data, &g)
		post("unlock", map[string]string{"grant": g.Grant, "dek": crypto.Encode(dek)}, "")
	}
	// Approval/revocation intentionally works without the DEK. Data remains locked.
	binary := filepath.Join(dir, "warden")
	build := exec.Command("go", "build", "-o", binary, "./cmd/warden")
	build.Dir = "../../.."
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("CLI build: %v %s", e, output)
	}
	type device struct {
		env             []string
		config          string
		process         *exec.Cmd
		id, fingerprint string
	}
	devices := make([]*device, 2)
	for n := range devices {
		cache := filepath.Join(dir, fmt.Sprintf("device-%d", n))
		os.MkdirAll(cache, 0700)
		path := filepath.Join(cache, "client.json")
		data, _ := json.Marshal(map[string]string{"api_base_url": origin, "ca_certificate": certPath, "timeout": "3s"})
		os.WriteFile(path, data, 0600)
		devices[n] = &device{env: append(os.Environ(), "XDG_CACHE_HOME="+cache), config: path}
	}
	startAgent := func(d *device) {
		t.Helper()
		d.process = exec.Command(binary, "agent", "serve")
		d.process.Env = d.env
		if e := d.process.Start(); e != nil {
			t.Fatal(e)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, e := os.Stat(filepath.Join(filepath.Dir(d.config), "warden/agent/credentials-v2.json")); e == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("agent readiness failed")
	}
	cli := func(d *device, args ...string) (string, error) {
		t.Helper()
		c := exec.Command(binary, append([]string{"--config", d.config, "-n"}, args...)...)
		c.Env = d.env
		out, e := c.CombinedOutput()
		return string(out), e
	}
	for _, d := range devices {
		startAgent(d)
		defer stop(&d.process)
	}
	type loginResult struct {
		out string
		err error
	}
	logins := make(chan loginResult, 2)
	for _, d := range devices {
		go func(d *device) { out, e := cli(d, "login"); logins <- loginResult{out, e} }(d)
	}
	for range devices {
		result := <-logins
		if result.err == nil || !strings.Contains(result.out, "Web approval required") {
			t.Fatal("first simultaneous login did not give bounded actionable approval", result.err, result.out)
		}
	}
	code, data := request("GET", "/api/v1/auth/clients/list", nil, "")
	if code != 200 {
		t.Fatal(code)
	}
	var listed struct {
		Pending []pairing `json:"pending"`
	}
	json.Unmarshal(data, &listed)
	if len(listed.Pending) != 2 {
		t.Fatal("two devices did not own separate pending requests")
	}
	for _, d := range devices {
		out, _ := cli(d, "status")
		_ = out // CLI status never returns a secret.
		// Correlate only public request IDs present in each CLI enrollment message.
		time.Sleep(time.Second)
		out, e := cli(d, "login")
		if e == nil {
			t.Fatal("unapproved login activated")
		}
		for _, pending := range listed.Pending {
			if strings.Contains(out, pending.ID) {
				d.id = pending.ID
				d.fingerprint = pending.Commitment
			}
		}
		if d.id == "" {
			t.Fatal("request ownership correlation failed", out)
		}
		body := map[string]string{"id": d.id, "commitment": d.fingerprint}
		post("clients/approve", body, grantFor("client_approve", "/api/v1/auth/clients/approve", body))
		time.Sleep(time.Second)
		if out, e = cli(d, "login"); e != nil {
			t.Fatal("approved login failed", e, out)
		}
		if out, e = cli(d, "config", "search", "fixture"); e == nil || !strings.Contains(out, "vault_locked") {
			t.Fatal("credential unlocked server", e, out)
		}
	}
	if devices[0].id == devices[1].id || devices[0].fingerprint == devices[1].fingerprint {
		t.Fatal("two agent credentials swapped or shared")
	}
	unlock()
	for _, body := range []struct {
		path string
		body any
	}{{"ssh-connections", map[string]any{"name": "fixture-ssh", "host": "fixture.invalid", "port": 22, "username": "fixture", "password": "synthetic-remote-password", "jump_connection_ids": "[]"}}, {"db-connections", map[string]any{"name": "fixture-db", "host": "fixture.invalid", "port": 3306, "username": "fixture", "password": "synthetic-db-password", "database": "fixture"}}} {
		if code, data := request("POST", "/api/v1/"+body.path, body.body, ""); code != 201 {
			t.Fatal(body.path, code, string(data))
		}
	}
	for _, d := range devices {
		if out, e := cli(d, "config", "search", "fixture"); e != nil || !strings.Contains(out, "fixture-ssh") {
			t.Fatal(e, out)
		}
		helper := exec.Command(os.Args[0], "-test.run=^TestT4ClientCapabilitiesHelper$", "-test.count=1")
		helper.Env = append(d.env, "WARDEN_T4_CLIENT_FIXTURE="+d.config)
		if out, e := helper.CombinedOutput(); e != nil {
			t.Fatalf("capabilities: %v %s", e, out)
		}
	}
	if out, e := cli(devices[0], "report", "create", "fixture-project", "--title", "fixture", "--summary", "synthetic", "--agent-model", "standards-fixture"); e != nil {
		t.Fatal(e, out)
	}
	stop(&serverProcess)
	hc.CloseIdleConnections()
	startServer()
	for _, d := range devices {
		if out, e := cli(d, "status"); e != nil || strings.TrimSpace(out) != "approved" {
			t.Fatal("server restart lost authorization", e, out)
		}
		if out, e := cli(d, "config", "search", "fixture"); e == nil || !strings.Contains(out, "vault_locked") {
			t.Fatal("restart not locked", e, out)
		}
	}
	unlock()
	body := map[string]string{"id": devices[0].id}
	post("clients/revoke", body, grantFor("client_revoke", "/api/v1/auth/clients/revoke", body))
	if out, e := cli(devices[0], "config", "search", "fixture"); e == nil || !strings.Contains(out, "unauthorized") {
		t.Fatal("web revoke did not immediately deny next API", e, out)
	}
	if out, e := cli(devices[1], "config", "search", "fixture"); e != nil {
		t.Fatal("other device revoked", e, out)
	}
	stop(&devices[1].process)
	startAgent(devices[1])
	if out, e := cli(devices[1], "status"); e != nil || strings.TrimSpace(out) != "unpaired" {
		t.Fatal("agent restart resumed credential", e, out)
	}
	if out, e := cli(devices[1], "login"); e == nil || !strings.Contains(out, "Web approval required") {
		t.Fatal("restart did not require new approval", e, out)
	}
	if out, e := cli(devices[1], "logout"); e != nil || strings.TrimSpace(out) != "logged_out" {
		t.Fatal(e, out)
	}
}
