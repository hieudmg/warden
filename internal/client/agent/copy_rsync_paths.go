package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"warden/internal/client/sftp"
)

func absoluteLocalRsyncPath(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	if filepath.VolumeName(name) != "" || os.IsPathSeparator(name[0]) {
		return "", errors.New("rsync requires a fully qualified path when using a drive or rooted path")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return cwd + string(os.PathSeparator) + name, nil
}

func absoluteRemoteRsyncPath(remote *sftp.Remote, name string) (string, error) {
	if path.IsAbs(name) {
		return name, nil
	}
	cwd, err := remote.WorkingDirectory()
	if err != nil {
		return "", fmt.Errorf("rsync: resolve remote working directory: %w", err)
	}
	if !path.IsAbs(cwd) {
		return "", errors.New("rsync: expected an absolute POSIX working directory from SFTP")
	}
	return strings.TrimSuffix(cwd, "/") + "/" + name, nil
}

func rsyncSeparator(remote bool, c byte) bool {
	if remote {
		return c == '/'
	}
	return os.IsPathSeparator(c)
}

// inspectRsyncPath checks raw prefixes before normalization. In particular,
// Lstat("link/") may follow link, and Clean("link/../target") hides link.
func inspectRsyncPath(ep sftp.Endpoint, remote, allowMissing bool) (os.FileInfo, error) {
	name := ep.Path
	windows := runtime.GOOS == "windows" && !remote
	volume := 0
	if windows {
		vol := filepath.VolumeName(name)
		volume = len(vol)
		if !utf8.ValidString(name) || !filepath.IsAbs(name) || !validRsyncVolume(vol) {
			return nil, fmt.Errorf("unsafe Windows path %q", name)
		}
		if volume == len(name) && volume > 2 { // a bare UNC share root
			return ep.FS.Lstat(name)
		}
	}
	if strings.ContainsRune(name, 0) || volume >= len(name) || !rsyncSeparator(remote, name[volume]) {
		return nil, fmt.Errorf("invalid absolute path %q", name)
	}
	last := volume + 1
	var info os.FileInfo
	missing := false
	for i := last; i <= len(name); i++ {
		if i < len(name) && !rsyncSeparator(remote, name[i]) {
			continue
		}
		if i == last && i != len(name) {
			last++
			continue
		}
		component := name[last:i]
		last = i + 1
		if missing && (component == "." || component == "..") {
			return nil, fmt.Errorf("dot component after missing directory in %q", name)
		}
		if windows && component != "" && component != "." && component != ".." && !validRsyncName(component, true) {
			return nil, fmt.Errorf("unsafe Windows path component %q", component)
		}
		if component == "" && info != nil {
			continue
		}
		var err error
		info, err = ep.FS.Lstat(name[:i])
		if err != nil {
			if allowMissing && errors.Is(err, os.ErrNotExist) {
				missing = true
				continue
			}
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("path component %q is a symlink", name[:i])
		}
		if i < len(name) && !info.IsDir() {
			return nil, fmt.Errorf("path component %q is not a directory", name[:i])
		}
	}
	return info, nil
}

// Device namespace routes aren't ordinary drive paths or UNC shares.
func validRsyncVolume(volume string) bool {
	if len(volume) == 2 && volume[1] == ':' {
		letter := volume[0] | 0x20
		return letter >= 'a' && letter <= 'z'
	}
	if len(volume) < 5 || !os.IsPathSeparator(volume[0]) || !os.IsPathSeparator(volume[1]) {
		return false
	}
	server, share, found := strings.Cut(strings.ReplaceAll(volume[2:], `\`, "/"), "/")
	return found && validRsyncName(server, true) && validRsyncName(share, true)
}

func validRsyncName(name string, windows bool) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return false
	}
	if windows {
		return utf8.ValidString(name) && filepath.IsLocal(name) && !strings.ContainsAny(name, `\:<>"|?*`) &&
			!strings.ContainsFunc(name, func(r rune) bool { return r < 32 }) && !strings.HasSuffix(name, " ") && !strings.HasSuffix(name, ".")
	}
	return true
}

func validateRsyncChild(name string, windows bool) error {
	if !validRsyncName(name, windows) {
		return fmt.Errorf("unsafe source entry name %q", name)
	}
	if windows && looksLikeWindowsShortName(name) {
		return fmt.Errorf("source entry %q could be a Windows short-name alias", name)
	}
	return nil
}

// Reject names that could resolve to an automatically generated DOS alias
// once another entry in the download has been created.
func looksLikeWindowsShortName(name string) bool {
	stem, ext, _ := strings.Cut(name, ".")
	if utf8.RuneCountInString(stem) > 8 || utf8.RuneCountInString(ext) > 3 || strings.Contains(ext, ".") {
		return false
	}
	i := strings.LastIndexByte(stem, '~')
	if i <= 0 || i == len(stem)-1 {
		return false
	}
	for _, c := range stem[i+1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type windowsRsyncNames [2]map[string]string

func windowsRsyncNameKeys(name string) [2]string {
	// Use both simple folding and uppercase matching. They disagree on
	// characters such as the Kelvin sign and dotless i, so reject either
	// kind of collision rather than relying on a destination's case table.
	fold := strings.Map(func(r rune) rune {
		key := r
		for other := unicode.SimpleFold(r); other != r; other = unicode.SimpleFold(other) {
			key = min(key, other)
		}
		return key
	}, name)
	return [2]string{strings.ToUpper(name), fold}
}

func (set *windowsRsyncNames) add(name string) {
	for i, key := range windowsRsyncNameKeys(name) {
		if set[i] == nil {
			set[i] = make(map[string]string)
		}
		set[i][key] = name
	}
}

func (set windowsRsyncNames) match(name string) string {
	for i, key := range windowsRsyncNameKeys(name) {
		if existing := set[i][key]; existing != "" {
			return existing
		}
	}
	return ""
}

func readWindowsRsyncNames(dir sftp.Endpoint) (windowsRsyncNames, error) {
	var names windowsRsyncNames
	entries, err := dir.FS.ReadDir(dir.Path)
	if err != nil {
		return names, fmt.Errorf("read destination directory %q: %w", dir.Path, err)
	}
	for _, entry := range entries {
		names.add(entry.Name())
	}
	return names, nil
}

type rsyncTreePolicy struct {
	goSender           bool
	windowsDestination bool
}

// checkRsyncTree rejects unsupported sources and pre-existing destinations
// that rsync must not follow or unlink. The only permitted kind change is a
// source subdirectory replacing an existing regular file. The checks, like
// SFTP's path checks, do not lock out concurrent filesystem changes.
func checkRsyncTree(ctx context.Context, source, target sftp.Endpoint, targetExists bool, policy rsyncTreePolicy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := source.FS.ReadDir(source.Path)
	if err != nil {
		return fmt.Errorf("read source directory %q: %w", source.Path, err)
	}
	var seen, listed windowsRsyncNames
	if policy.windowsDestination && targetExists && len(entries) != 0 {
		listed, err = readWindowsRsyncNames(target)
		if err != nil {
			return err
		}
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if err := validateRsyncChild(name, policy.windowsDestination); err != nil {
			return err
		}
		if policy.windowsDestination {
			if prior := seen.match(name); prior != "" {
				return fmt.Errorf("colliding Windows sibling names %q and %q in %q", prior, name, source.Path)
			}
			seen.add(name)
		}
		src, dst := source, target
		src.Path, dst.Path = src.FS.Join(src.Path, name), dst.FS.Join(dst.Path, name)
		info, err := src.FS.Lstat(src.Path)
		if err != nil {
			return fmt.Errorf("source %q: %w", src.Path, err)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("source %q is a symlink or special file", src.Path)
		}
		if policy.goSender && info.IsDir() && !utf8.ValidString(name) {
			// The Go sender recurses through fs.WalkDir, which cannot open
			// non-UTF-8 relative directory paths in its rooted fs.FS.
			return fmt.Errorf("source directory %q is not valid UTF-8; use --backend=sftp", src.Path)
		}
		var dstDir bool
		if targetExists {
			dstInfo, err := dst.FS.Lstat(dst.Path)
			switch {
			case errors.Is(err, os.ErrNotExist):
			case err != nil:
				return fmt.Errorf("destination %q: %w", dst.Path, err)
			case policy.windowsDestination && listed.match(name) == "":
				return fmt.Errorf("destination %q resolves through an unlisted Windows alias", dst.Path)
			case dstInfo.IsDir():
				if !info.IsDir() {
					return fmt.Errorf("refusing to replace destination directory %q with a file", dst.Path)
				}
				dstDir = true
			case !dstInfo.Mode().IsRegular():
				return fmt.Errorf("destination %q is a symlink or special file", dst.Path)
			}
		}
		if info.IsDir() {
			if err := checkRsyncTree(ctx, src, dst, dstDir, policy); err != nil {
				return err
			}
		}
	}
	return nil
}
