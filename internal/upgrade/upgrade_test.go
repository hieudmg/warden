package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"
)

func TestAssetName(t *testing.T) {
	tests := []struct {
		name    string
		kind    Kind
		goos    string
		goarch  string
		want    string
		wantErr string
	}{
		{name: "linux client", kind: Client, goos: "linux", goarch: "amd64", want: "warden-linux-amd64"},
		{name: "windows client", kind: Client, goos: "windows", goarch: "amd64", want: "warden.exe"},
		{name: "linux server", kind: Server, goos: "linux", goarch: "amd64", want: "warden-server-linux-amd64"},
		{name: "windows server unavailable", kind: Server, goos: "windows", goarch: "amd64", wantErr: "no suitable release binary"},
		{name: "linux arm unavailable", kind: Client, goos: "linux", goarch: "arm64", wantErr: "no suitable release binary"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := assetName(tc.kind, tc.goos, tc.goarch)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("assetName() error = nil, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("assetName() error = %q, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("assetName() error = %v, want nil", err)
			}
			if got != tc.want {
				t.Fatalf("assetName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUpgradeDownloadsAndVerifies(t *testing.T) {
	const asset = "warden-linux-amd64"
	const payload = "new warden binary"
	dir, exe := newExecutable(t, "warden", "old warden binary")
	srv, requests := releaseServer(t, map[string]string{
		"/" + asset:        payload,
		"/" + checksumFile: sha256Hex(payload) + "  " + asset + "\n",
	})

	var calls []replaceCall
	result, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
		Replace:        recordReplace(&calls),
	})
	if err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}

	if got, want := requests.list(), []string{"/" + asset, "/" + checksumFile}; !slices.Equal(got, want) {
		t.Errorf("requested paths = %v, want %v", got, want)
	}
	if want := (Result{Asset: asset, ExecutablePath: exe}); result != want {
		t.Errorf("Upgrade() result = %+v, want %+v", result, want)
	}
	if len(calls) != 1 {
		t.Fatalf("Replace called %d times, want 1", len(calls))
	}
	call := calls[0]
	if call.executablePath != exe {
		t.Errorf("Replace executablePath = %q, want %q", call.executablePath, exe)
	}
	if call.mode != 0o755 {
		t.Errorf("Replace mode = %v, want 0755", call.mode)
	}
	if string(call.content) != payload {
		t.Errorf("Replace content = %q, want %q", call.content, payload)
	}
	if got := filepath.Dir(call.tempPath); got != dir {
		t.Errorf("Replace tempPath dir = %q, want %q", got, dir)
	}
	assertFileContent(t, exe, "old warden binary")
	assertDirEntries(t, dir, "warden")
}

func TestUpgradeRejectsChecksumMismatch(t *testing.T) {
	const asset = "warden-linux-amd64"
	dir, exe := newExecutable(t, "warden", "old warden binary")
	srv, _ := releaseServer(t, map[string]string{
		"/" + asset:        "tampered binary",
		"/" + checksumFile: sha256Hex("expected binary") + "  " + asset + "\n",
	})

	var calls []replaceCall
	_, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
		Replace:        recordReplace(&calls),
	})
	if err == nil {
		t.Fatal("Upgrade() error = nil, want checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("Upgrade() error = %q, want it to mention checksum", err)
	}
	if len(calls) != 0 {
		t.Errorf("Replace called %d times, want 0", len(calls))
	}
	assertFileContent(t, exe, "old warden binary")
	assertDirEntries(t, dir, "warden")
}

func TestUpgradeRejectsMissingChecksum(t *testing.T) {
	const asset = "warden-linux-amd64"
	dir, exe := newExecutable(t, "warden", "old warden binary")
	srv, _ := releaseServer(t, map[string]string{
		"/" + asset:        "new warden binary",
		"/" + checksumFile: sha256Hex("other") + "  warden-server-linux-amd64\n",
	})

	var calls []replaceCall
	_, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
		Replace:        recordReplace(&calls),
	})
	if err == nil {
		t.Fatal("Upgrade() error = nil, want missing checksum error")
	}
	if !strings.Contains(err.Error(), asset) {
		t.Errorf("Upgrade() error = %q, want it to mention %q", err, asset)
	}
	if len(calls) != 0 {
		t.Errorf("Replace called %d times, want 0", len(calls))
	}
	assertFileContent(t, exe, "old warden binary")
	assertDirEntries(t, dir, "warden")
}

func TestUpgradeRejectsUnavailableAsset(t *testing.T) {
	const asset = "warden-linux-amd64"
	dir, exe := newExecutable(t, "warden", "old warden binary")
	srv, _ := releaseServer(t, map[string]string{
		"/" + checksumFile: sha256Hex("new warden binary") + "  " + asset + "\n",
	})

	var calls []replaceCall
	_, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
		Replace:        recordReplace(&calls),
	})
	if err == nil {
		t.Fatal("Upgrade() error = nil, want unavailable asset error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("Upgrade() error = %q, want it to mention 404", err)
	}
	if len(calls) != 0 {
		t.Errorf("Replace called %d times, want 0", len(calls))
	}
	assertFileContent(t, exe, "old warden binary")
	assertDirEntries(t, dir, "warden")
}

func TestUpgradeAcceptsReleaseChecksumFormat(t *testing.T) {
	const asset = "warden-linux-amd64"
	const payload = "new warden binary"
	dir, exe := newExecutable(t, "warden", "old warden binary")
	// The release script writes "sha256sum ./*" output, so entries are ./asset.
	srv, _ := releaseServer(t, map[string]string{
		"/" + asset:        payload,
		"/" + checksumFile: sha256Hex(payload) + "  ./" + asset + "\n",
	})

	var calls []replaceCall
	if _, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
		Replace:        recordReplace(&calls),
	}); err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("Replace called %d times, want 1", len(calls))
	}
	if string(calls[0].content) != payload {
		t.Errorf("Replace content = %q, want %q", calls[0].content, payload)
	}
	assertDirEntries(t, dir, "warden")
}

func TestUpgradeRejectsUnsupportedTargetBeforeDownload(t *testing.T) {
	dir, exe := newExecutable(t, "warden", "old warden binary")
	srv, requests := releaseServer(t, map[string]string{})

	var calls []replaceCall
	_, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "arm64",
		ExecutablePath: exe,
		Replace:        recordReplace(&calls),
	})
	if err == nil {
		t.Fatal("Upgrade() error = nil, want unsupported target error")
	}
	if !strings.Contains(err.Error(), "no suitable release binary") {
		t.Errorf("Upgrade() error = %q, want it to mention no suitable release binary", err)
	}
	if got := requests.list(); len(got) != 0 {
		t.Errorf("requested paths = %v, want none", got)
	}
	if len(calls) != 0 {
		t.Errorf("Replace called %d times, want 0", len(calls))
	}
	assertFileContent(t, exe, "old warden binary")
	assertDirEntries(t, dir, "warden")
}

func TestUpgradeAcceptsAny2xxResponse(t *testing.T) {
	const asset = "warden-linux-amd64"
	const payload = "new warden binary"
	dir, exe := newExecutable(t, "warden", "old warden binary")
	// GitHub's CDN may answer with 201 rather than 200; every 2xx is success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + asset:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, payload)
		case "/" + checksumFile:
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, sha256Hex(payload)+"  "+asset+"\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	var calls []replaceCall
	result, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
		Replace:        recordReplace(&calls),
	})
	if err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}
	if want := (Result{Asset: asset, ExecutablePath: exe}); result != want {
		t.Errorf("Upgrade() result = %+v, want %+v", result, want)
	}
	if len(calls) != 1 {
		t.Fatalf("Replace called %d times, want 1", len(calls))
	}
	if string(calls[0].content) != payload {
		t.Errorf("Replace content = %q, want %q", calls[0].content, payload)
	}
	assertDirEntries(t, dir, "warden")
}

func TestFetchChecksumUsesFirstMatchingEntry(t *testing.T) {
	const asset = "warden-linux-amd64"
	const first = "1111111111111111111111111111111111111111111111111111111111111111"
	const second = "2222222222222222222222222222222222222222222222222222222222222222"
	srv, _ := releaseServer(t, map[string]string{
		"/" + checksumFile: first + "  " + asset + "\n" + second + "  " + asset + "\n",
	})

	got, err := fetchChecksum(context.Background(), srv.Client(), srv.URL+"/"+checksumFile, asset)
	if err != nil {
		t.Fatalf("fetchChecksum() error = %v", err)
	}
	if got != first {
		t.Errorf("fetchChecksum() = %q, want first matching entry %q", got, first)
	}
}

func TestUpgradeRejectsMissingExecutableBeforeDownload(t *testing.T) {
	const asset = "warden-linux-amd64"
	dir := t.TempDir()
	exe := filepath.Join(dir, "missing-warden")
	srv, requests := releaseServer(t, map[string]string{
		"/" + asset:        "new warden binary",
		"/" + checksumFile: sha256Hex("new warden binary") + "  " + asset + "\n",
	})

	var calls []replaceCall
	_, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
		Replace:        recordReplace(&calls),
	})
	if err == nil {
		t.Fatal("Upgrade() error = nil, want executable stat error")
	}
	if !strings.Contains(err.Error(), "inspect executable") {
		t.Errorf("Upgrade() error = %q, want it to mention inspect executable", err)
	}
	if got := requests.list(); len(got) != 0 {
		t.Errorf("requested paths = %v, want none", got)
	}
	if len(calls) != 0 {
		t.Errorf("Replace called %d times, want 0", len(calls))
	}
	assertDirEntries(t, dir)
}

func TestReplaceExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows schedules a PowerShell helper that replaces the executable after this process exits")
	}
	dir := t.TempDir()
	current := filepath.Join(dir, "current")
	download := filepath.Join(dir, "download")
	// A non-default mode catches an implementation that always chmods 0755.
	if err := os.WriteFile(current, []byte("old binary"), 0o711); err != nil {
		t.Fatalf("write current: %v", err)
	}
	if err := os.Chmod(current, 0o711); err != nil {
		t.Fatalf("chmod current: %v", err)
	}
	if err := os.WriteFile(download, []byte("new binary"), 0o600); err != nil {
		t.Fatalf("write download: %v", err)
	}

	scheduled, err := replaceExecutable(download, current, 0o711)
	if err != nil {
		t.Fatalf("replaceExecutable() error = %v", err)
	}
	if scheduled {
		t.Fatalf("replaceExecutable() scheduled = true, want false on %s", runtime.GOOS)
	}
	assertFileContent(t, current, "new binary")
	if got := fileMode(t, current); got != 0o711 {
		t.Errorf("current mode = %v, want preserved 0711", got)
	}
	if _, err := os.Stat(download); !os.IsNotExist(err) {
		t.Errorf("temporary source still present after replacement: err = %v", err)
	}
}

func TestReplaceExecutableFailureLeavesTargetUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows schedules a PowerShell helper that replaces the executable after this process exits")
	}

	t.Run("missing parent directory", func(t *testing.T) {
		dir := t.TempDir()
		download := filepath.Join(dir, "download")
		if err := os.WriteFile(download, []byte("new binary"), 0o600); err != nil {
			t.Fatalf("write download: %v", err)
		}
		target := filepath.Join(dir, "missing", "current")

		if _, err := replaceExecutable(download, target, 0o755); err == nil {
			t.Fatal("replaceExecutable() error = nil, want rename failure")
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Errorf("target exists after failed replacement: err = %v", err)
		}
		// A failed replacement must not destroy the verified download; Upgrade
		// removes it through its deferred cleanup.
		assertFileContent(t, download, "new binary")
	})

	t.Run("destination is an existing directory", func(t *testing.T) {
		dir := t.TempDir()
		download := filepath.Join(dir, "download")
		if err := os.WriteFile(download, []byte("new binary"), 0o600); err != nil {
			t.Fatalf("write download: %v", err)
		}
		target := filepath.Join(dir, "current")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("mkdir target: %v", err)
		}
		old := filepath.Join(target, "old")
		if err := os.WriteFile(old, []byte("old binary"), 0o755); err != nil {
			t.Fatalf("write old: %v", err)
		}

		if _, err := replaceExecutable(download, target, 0o755); err == nil {
			t.Fatal("replaceExecutable() error = nil, want rename failure")
		}
		assertFileContent(t, old, "old binary")
	})
}

func TestUpgradeReplacesExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows defers replacement to a PowerShell helper that runs after this process exits")
	}
	const asset = "warden-linux-amd64"
	const payload = "new warden binary"
	dir, exe := newExecutable(t, "warden", "old warden binary")
	srv, _ := releaseServer(t, map[string]string{
		"/" + asset:        payload,
		"/" + checksumFile: sha256Hex(payload) + "  " + asset + "\n",
	})

	// Leaving Replace nil exercises the platform replacement default.
	result, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
	})
	if err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}
	if want := (Result{Asset: asset, ExecutablePath: exe}); result != want {
		t.Errorf("Upgrade() result = %+v, want %+v", result, want)
	}
	assertFileContent(t, exe, payload)
	if got := fileMode(t, exe); got != 0o755 {
		t.Errorf("executable mode = %v, want preserved 0755", got)
	}
	// The verified download must not survive a successful replacement.
	assertDirEntries(t, dir, "warden")
}

func TestUpgradePreservesAdjacentState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows defers replacement to a PowerShell helper that runs after this process exits")
	}
	const asset = "warden-server-linux-amd64"
	const payload = "new warden-server binary"
	dir, exe := newExecutable(t, "warden-server", "old warden-server binary")
	state := map[string]string{
		"client.json":           `{"server":"https://warden.example"}`,
		"server.json":           `{"listen":"127.0.0.1:8080"}`,
		"warden.db":             "sqlite database bytes",
		"master.key":            "0123456789abcdef0123456789abcdef",
		"warden-server.service": "[Service]\nExecStart=/usr/local/bin/warden-server serve\n",
	}
	names := make([]string, 0, len(state)+1)
	names = append(names, "warden-server")
	for name, content := range state {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		names = append(names, name)
	}
	srv, _ := releaseServer(t, map[string]string{
		"/" + asset:        payload,
		"/" + checksumFile: sha256Hex(payload) + "  " + asset + "\n",
	})

	if _, err := Upgrade(context.Background(), Server, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
	}); err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}

	assertFileContent(t, exe, payload)
	for name, content := range state {
		assertFileContent(t, filepath.Join(dir, name), content)
	}
	if got := fileMode(t, filepath.Join(dir, "master.key")); got != 0o600 {
		t.Errorf("master.key mode = %v, want preserved 0600", got)
	}
	assertDirEntries(t, dir, names...)
}

func TestUpgradePreservesExecutableMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows defers replacement to a PowerShell helper that runs after this process exits")
	}
	const asset = "warden-linux-amd64"
	const payload = "new warden binary"
	dir, exe := newExecutable(t, "warden", "old warden binary")
	// A non-default mode catches an implementation that always chmods 0755.
	if err := os.Chmod(exe, 0o711); err != nil {
		t.Fatalf("chmod executable: %v", err)
	}
	srv, _ := releaseServer(t, map[string]string{
		"/" + asset:        payload,
		"/" + checksumFile: sha256Hex(payload) + "  " + asset + "\n",
	})

	if _, err := Upgrade(context.Background(), Client, Options{
		ReleaseBaseURL: srv.URL,
		HTTPClient:     srv.Client(),
		GOOS:           "linux",
		GOARCH:         "amd64",
		ExecutablePath: exe,
	}); err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}

	assertFileContent(t, exe, payload)
	if got := fileMode(t, exe); got != 0o711 {
		t.Errorf("executable mode = %v, want preserved 0711", got)
	}
	assertDirEntries(t, dir, "warden")
}

// The Windows helper runs only on Windows, so its command construction is
// verified statically: paths must never reach the command line, and the encoded
// program must round-trip.
func TestWindowsHelperPassesPathsThroughEnvironment(t *testing.T) {
	tempPath := `C:\Users\%PATH%\warden.exe.upgrade-1234`
	executablePath := `C:\Program Files\100% & "quoted" 'single'\warden.exe`

	encoded := encodePowerShellCommand(windowsHelperProgram)
	for _, r := range encoded {
		switch r {
		case ' ', '"', '\'', '&', '|', '<', '>', '^', '%':
			t.Fatalf("encoded command contains shell-significant character %q", r)
		}
	}

	program := decodePowerShellCommand(t, encoded)
	if program != windowsHelperProgram {
		t.Fatal("encoded command did not round-trip to the helper program")
	}
	for _, needle := range []string{tempPath, executablePath, "%PATH%", `"quoted"`, "&"} {
		if strings.Contains(program, needle) {
			t.Errorf("helper program embeds %q; paths must travel through the environment", needle)
		}
	}

	want := map[string]string{
		windowsHelperSourceEnv:    tempPath,
		windowsHelperTargetEnv:    executablePath,
		windowsHelperParentPIDEnv: "4242",
	}
	got := make(map[string]string, len(want))
	for _, entry := range windowsHelperEnv(tempPath, executablePath, 4242) {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("environment entry %q has no name/value separator", entry)
		}
		got[name] = value
	}
	if !maps.Equal(got, want) {
		t.Errorf("helper environment = %q, want literal values %q", got, want)
	}
}

func TestWindowsHelperWaitsAndRetriesMove(t *testing.T) {
	program := windowsHelperProgram
	for _, want := range []string{
		"$env:" + windowsHelperSourceEnv,
		"$env:" + windowsHelperTargetEnv,
		"$env:" + windowsHelperParentPIDEnv,
		"WaitForExit",
		"while (",
		"Move-Item -LiteralPath",
	} {
		if !strings.Contains(program, want) {
			t.Errorf("helper program missing %q", want)
		}
	}
	for _, unwanted := range []string{"cmd.exe", "del /f", "del /q", "ping -n"} {
		if strings.Contains(program, unwanted) {
			t.Errorf("helper program still contains legacy shell helper text %q", unwanted)
		}
	}
	// The verified download may only be removed once the retry loop gives up.
	loop := strings.Index(program, "while (")
	cleanup := strings.Index(program, "Remove-Item")
	if loop < 0 || cleanup < 0 || cleanup < loop {
		t.Error("helper program removes the verified download before the retry loop")
	}
}

type replaceCall struct {
	tempPath       string
	executablePath string
	mode           fs.FileMode
	content        []byte
}

func recordReplace(calls *[]replaceCall) func(string, string, fs.FileMode) (bool, error) {
	return func(tempPath, executablePath string, mode fs.FileMode) (bool, error) {
		content, err := os.ReadFile(tempPath)
		*calls = append(*calls, replaceCall{tempPath: tempPath, executablePath: executablePath, mode: mode, content: content})
		if err != nil {
			return false, err
		}
		return false, nil
	}
}

type requestRecorder struct {
	mu    sync.Mutex
	paths []string
}

func (r *requestRecorder) add(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, path)
}

func (r *requestRecorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.paths)
}

func releaseServer(t *testing.T, files map[string]string) (*httptest.Server, *requestRecorder) {
	t.Helper()
	requests := &requestRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.add(r.URL.Path)
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("write %s: %v", r.URL.Path, err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, requests
}

func newExecutable(t *testing.T, name, content string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	return dir, path
}

func decodePowerShellCommand(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode command: %v", err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("decoded command has odd byte length %d", len(raw))
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(units))
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func fileMode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Errorf("%s content = %q, want %q", path, got, want)
	}
}

func assertDirEntries(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	sort.Strings(want)
	if !slices.Equal(names, want) {
		t.Errorf("entries in %s = %v, want %v", dir, names, want)
	}
}
