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

// Options configures an upgrade. Empty fields use the production defaults
// described in the design doc.
type Options struct {
	Repo           string
	ReleaseBaseURL string
	HTTPClient     *http.Client
	GOOS           string
	GOARCH         string
	ExecutablePath string
	Replace        func(tempPath, executablePath string, mode fs.FileMode) (scheduled bool, err error)
	settings       *downloadSettings
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

	// Windows process-creation flags. Keep these platform-independent so the
	// helper lifecycle contract can be tested on every development platform.
	windowsCreateNewProcessGroup = 0x00000200
	windowsDetachedProcess       = 0x00000008
)

// windowsHelperCreationFlags prevents the replacement helper from inheriting
// the caller's console, while keeping it in an isolated process group. The
// helper must outlive the command that starts it to replace its executable.
func windowsHelperCreationFlags() uint32 {
	return windowsCreateNewProcessGroup | windowsDetachedProcess
}

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

# Atomically replace the target with the verified download. It can stay locked
# briefly while the previous process shuts down, so retry instead of discarding
# the verified download on the first failure.
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
    try {
        [IO.File]::Replace($source, $target, $null)
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

	settings := defaultDownloadSettings
	if opts.settings != nil {
		settings = *opts.settings
	}
	ctx, cancel := context.WithTimeout(ctx, settings.total)
	defer cancel()
	client, err := downloadClient(opts.HTTPClient, settings)
	if err != nil {
		return Result{}, err
	}
	defer client.CloseIdleConnections()
	baseURL := releaseBaseURL(repo, opts.ReleaseBaseURL)
	if err := httpsURL(baseURL); err != nil {
		return Result{}, err
	}
	executablePath := opts.ExecutablePath
	if executablePath == "" {
		executablePath, err = os.Executable()
		if err != nil {
			return Result{}, fmt.Errorf("resolve executable path: %w", err)
		}
	}
	info, err := os.Lstat(executablePath)
	if err != nil {
		return Result{}, fmt.Errorf("inspect executable %s: %w", executablePath, err)
	}
	if !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("inspect executable: target must be a regular file, not a symlink")
	}
	replace := opts.Replace
	if replace == nil {
		replace = replaceExecutable
	}

	temp, err := createUpgradeTemp(filepath.Dir(executablePath), "."+filepath.Base(executablePath)+".upgrade-")
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

	if err := download(ctx, client, baseURL+"/"+asset, temp, settings.binaryBytes); err != nil {
		_ = temp.Close()
		return Result{}, err
	}
	if err := temp.Close(); err != nil {
		return Result{}, fmt.Errorf("close %s: %w", tempPath, err)
	}

	if err := verifyChecksum(ctx, client, baseURL+"/"+checksumFile, asset, tempPath, settings.checksumBytes); err != nil {
		return Result{}, err
	}

	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	current, err := os.Lstat(executablePath)
	if err != nil || !os.SameFile(info, current) {
		return Result{}, fmt.Errorf("executable changed during download")
	}
	scheduled, err := replace(tempPath, executablePath, info.Mode().Perm())
	if err != nil {
		return Result{}, fmt.Errorf("replace %s: %w", executablePath, err)
	}
	preserveTemp = scheduled

	return Result{Asset: asset, ExecutablePath: executablePath, Scheduled: scheduled}, nil
}

func download(ctx context.Context, client *http.Client, url string, dst *os.File, limit int64) error {
	resp, err := get(ctx, client, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	n, err := io.Copy(dst, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	if n > limit {
		return fmt.Errorf("download exceeds %d bytes", limit)
	}
	return resp.Body.Close()
}

func verifyChecksum(ctx context.Context, client *http.Client, url, asset, path string, limit int64) error {
	want, err := fetchChecksumLimit(ctx, client, url, asset, limit)
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
// Accept exact sha256sum filenames, optionally ./-prefixed or binary-marked.
// The publisher writes sha256sum ./*; no basename or substring matching.
func fetchChecksum(ctx context.Context, client *http.Client, url, asset string) (string, error) {
	return fetchChecksumLimit(ctx, client, url, asset, maxChecksumBytes)
}
func fetchChecksumLimit(ctx context.Context, client *http.Client, url, asset string, limit int64) (string, error) {
	resp, err := get(ctx, client, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", url, err)
	}

	if err := resp.Body.Close(); err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("checksum exceeds %d bytes", limit)
	}
	var digest string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		// sha256sum uses a space and a text-space/binary-star marker.
		if len(line) < 67 || line[64] != ' ' || (line[65] != ' ' && line[65] != '*') {
			return "", fmt.Errorf("invalid SHA256SUMS entry")
		}
		raw, err := hex.DecodeString(line[:64])
		if err != nil || len(raw) != sha256.Size {
			return "", fmt.Errorf("invalid SHA256SUMS digest")
		}
		name := strings.TrimPrefix(line[66:], "./")
		if name == asset {
			if digest != "" {
				return "", fmt.Errorf("multiple checksum entries for %s", asset)
			}
			digest = strings.ToLower(line[:64])
		}
	}
	if digest == "" {
		return "", fmt.Errorf("checksum for %s not found in %s", asset, url)
	}
	return digest, nil
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

func get(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	if err := httpsURL(url); err != nil {
		return nil, err
	}
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
