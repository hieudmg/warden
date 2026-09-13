package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
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

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
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
