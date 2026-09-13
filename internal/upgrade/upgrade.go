package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	defaultRepo    = "hieudmg/warden"
	checksumFile   = "SHA256SUMS"
	defaultBaseURL = "https://github.com/%s/releases/latest/download"
)

// Kind selects which released binary an upgrade replaces.
type Kind uint8

const (
	Client Kind = iota
	Server
)

// Doer performs an HTTP request. It matches *http.Client.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Options configures an upgrade. Empty fields use the production defaults
// described in the design doc.
type Options struct {
	Repo           string
	ReleaseBaseURL string
	HTTPClient     Doer
	GOOS           string
	GOARCH         string
	ExecutablePath string
	Replace        func(tempPath, executablePath string, mode fs.FileMode) (scheduled bool, err error)
}

// Result reports the asset an upgrade used and whether replacement was
// scheduled for after the current process exits.
type Result struct {
	Asset          string
	ExecutablePath string
	Scheduled      bool
}

func kindName(kind Kind) string {
	switch kind {
	case Client:
		return "warden"
	case Server:
		return "warden-server"
	default:
		return "unknown binary"
	}
}

func assetName(kind Kind, goos, goarch string) (string, error) {
	switch {
	case kind == Client && goos == "linux" && goarch == "amd64":
		return "warden-linux-amd64", nil
	case kind == Client && goos == "windows" && goarch == "amd64":
		return "warden.exe", nil
	case kind == Server && goos == "linux" && goarch == "amd64":
		return "warden-server-linux-amd64", nil
	}
	return "", fmt.Errorf("no suitable release binary for %s (%s/%s)", kindName(kind), goos, goarch)
}

func releaseBaseURL(repo, override string) string {
	if override != "" {
		return strings.TrimRight(override, "/")
	}
	return fmt.Sprintf(defaultBaseURL, repo)
}

// Upgrade downloads, verifies, and replaces the released binary for kind.
// It never reads or writes configuration or state files.
func Upgrade(ctx context.Context, kind Kind, opts Options) (Result, error) {
	repo := opts.Repo
	if repo == "" {
		repo = defaultRepo
	}
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := opts.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	asset, err := assetName(kind, goos, goarch)
	if err != nil {
		return Result{}, err
	}

	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	executablePath := opts.ExecutablePath
	if executablePath == "" {
		executablePath, err = os.Executable()
		if err != nil {
			return Result{}, fmt.Errorf("resolve executable path: %w", err)
		}
	}
	info, err := os.Stat(executablePath)
	if err != nil {
		return Result{}, fmt.Errorf("inspect executable %s: %w", executablePath, err)
	}
	replace := opts.Replace
	if replace == nil {
		return Result{}, errors.New("upgrade: no replacement function configured")
	}

	baseURL := releaseBaseURL(repo, opts.ReleaseBaseURL)
	temp, err := os.CreateTemp(filepath.Dir(executablePath), "."+filepath.Base(executablePath)+".upgrade-*")
	if err != nil {
		return Result{}, fmt.Errorf("create temporary file beside %s: %w", executablePath, err)
	}
	tempPath := temp.Name()
	preserveTemp := false
	defer func() {
		if !preserveTemp {
			_ = os.Remove(tempPath)
		}
	}()

	if err := download(ctx, client, baseURL+"/"+asset, temp); err != nil {
		_ = temp.Close()
		return Result{}, err
	}
	if err := temp.Close(); err != nil {
		return Result{}, fmt.Errorf("close %s: %w", tempPath, err)
	}

	if err := verifyChecksum(ctx, client, baseURL+"/"+checksumFile, asset, tempPath); err != nil {
		return Result{}, err
	}

	scheduled, err := replace(tempPath, executablePath, info.Mode().Perm())
	if err != nil {
		return Result{}, fmt.Errorf("replace %s: %w", executablePath, err)
	}
	preserveTemp = scheduled

	return Result{Asset: asset, ExecutablePath: executablePath, Scheduled: scheduled}, nil
}

func download(ctx context.Context, client Doer, url string, dst *os.File) error {
	resp, err := get(ctx, client, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(dst, resp.Body); err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	return nil
}

func verifyChecksum(ctx context.Context, client Doer, url, asset, path string) error {
	want, err := fetchChecksum(ctx, client, url, asset)
	if err != nil {
		return err
	}
	got, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", asset, got, want)
	}
	return nil
}

// fetchChecksum returns the digest recorded for asset in a SHA256SUMS file.
// Entries may name the asset as "asset", "./asset", or "*asset", matching
// the release script and shell installers.
func fetchChecksum(ctx context.Context, client Doer, url, asset string) (string, error) {
	resp, err := get(ctx, client, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", url, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(fields[1], "./"), "*")
		if name == asset {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found in %s", asset, url)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func get(ctx context.Context, client Doer, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: unexpected status %s", url, resp.Status)
	}
	return resp, nil
}
