package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf16"
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

// Windows replacement helper contract.
//
// The program and its environment live here rather than in replace_windows.go
// so tests on every platform can verify that no path text reaches a command
// line. Windows locks a running executable, so replace_windows.go starts a
// detached helper that waits for this process to exit and then moves the
// verified download over the target.
const (
	windowsHelperSourceEnv    = "WARDEN_UPGRADE_SOURCE"
	windowsHelperTargetEnv    = "WARDEN_UPGRADE_TARGET"
	windowsHelperParentPIDEnv = "WARDEN_UPGRADE_PARENT_PID"
)

// windowsHelperProgram is the PowerShell program run through -EncodedCommand.
// It reads both paths from the environment, so Windows metacharacters such as
// %, &, ", and ' inside a path stay literal. It waits for the process holding
// the running-executable lock, retries the move while that lock clears, and
// removes the verified download only after the final retry fails.
const windowsHelperProgram = `$ErrorActionPreference = 'Stop'

$source = $env:WARDEN_UPGRADE_SOURCE
$target = $env:WARDEN_UPGRADE_TARGET
$parentId = 0
[void][int]::TryParse($env:WARDEN_UPGRADE_PARENT_PID, [ref]$parentId)

if ([string]::IsNullOrEmpty($source) -or [string]::IsNullOrEmpty($target)) { exit 2 }

# Wait for the process that holds the running-executable lock to exit.
$parent = Get-Process -Id $parentId -ErrorAction SilentlyContinue
if ($parent) { [void]$parent.WaitForExit(30000) }

# Move the verified download over the target. The destination can stay locked
# briefly while the previous process shuts down, so retry instead of discarding
# the verified download on the first failure.
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
    try {
        Move-Item -LiteralPath $source -Destination $target -Force -ErrorAction Stop
        exit 0
    } catch {
        Start-Sleep -Milliseconds 250
    }
}

# Reached only after every retry failed; the old executable is still intact.
Remove-Item -LiteralPath $source -Force -ErrorAction SilentlyContinue
exit 1
`

// windowsHelperEnv returns the helper environment entries. Values reach the
// child process verbatim and never pass through a command shell.
func windowsHelperEnv(tempPath, executablePath string, parentPID int) []string {
	return []string{
		windowsHelperSourceEnv + "=" + tempPath,
		windowsHelperTargetEnv + "=" + executablePath,
		windowsHelperParentPIDEnv + "=" + strconv.Itoa(parentPID),
	}
}

// encodePowerShellCommand encodes program as base64 UTF-16LE, the form accepted
// by powershell.exe -EncodedCommand. The result is a single argv element with no
// shell metacharacters, so no path text is ever parsed as shell syntax.
func encodePowerShellCommand(program string) string {
	units := utf16.Encode([]rune(program))
	raw := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	return base64.StdEncoding.EncodeToString(raw)
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
		replace = replaceExecutable
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
