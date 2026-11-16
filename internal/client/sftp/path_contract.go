package sftp

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// validateEntryName defines the portable component contract for recursive copy
// and source basenames appended to directories. It does not validate or rewrite
// caller-supplied full paths in the remote POSIX namespace.
func validateEntryName(name string) error {
	if !utf8.ValidString(name) || name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:<>"|?*`) || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return fmt.Errorf("copy: unsafe entry name %q", name)
	}
	for _, c := range name {
		if c < 32 {
			return fmt.Errorf("copy: unsafe entry name %q", name)
		}
	}
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.ToUpper(strings.TrimRight(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return fmt.Errorf("copy: reserved entry name %q", name)
	}
	if strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT") {
		suffix := stem[3:]
		if (len(suffix) == 1 && suffix[0] >= '1' && suffix[0] <= '9') || suffix == "¹" || suffix == "²" || suffix == "³" {
			return fmt.Errorf("copy: reserved entry name %q", name)
		}
	}
	return nil
}

// rejectSymlinkComponents inspects raw prefixes, never Join/Dir/Clean: those
// erase link/.. and hide terminal links behind a slash or dot. A missing path
// may be created, but cannot be traversed with .. to select an existing target.
// This is a static path check, not protection against concurrent replacement.
func rejectSymlinkComponents(fs Filesystem, p, volume, separators string) error {
	start := len(volume)
	var missing error
	for i := start; i <= len(p); i++ {
		if i < len(p) && !strings.ContainsRune(separators, rune(p[i])) {
			continue
		}
		if missing != nil && p[start:i] == ".." {
			return missing
		}
		end := i
		if i == len(volume) && i < len(p) {
			end++ // Inspect the root, not a Windows drive-relative "C:".
		}
		start = i + 1
		if end == 0 {
			continue
		}
		prefix := p[:end]
		info, err := fs.Lstat(prefix)
		if errors.Is(err, os.ErrNotExist) {
			if missing == nil {
				missing = err
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("copy: path component %q is a symlink", prefix)
		}
		if i < len(p) && !info.IsDir() {
			return fmt.Errorf("copy: path component %q is not a directory", prefix)
		}
	}
	return nil
}

func containedChild(fs Filesystem, root, name string) (string, error) {
	if err := validateEntryName(name); err != nil {
		return "", err
	}
	root, err := fs.Clean(root)
	if err != nil {
		return "", err
	}
	target := fs.Join(root, name)
	rel, err := fs.Rel(root, target)
	if err != nil || rel == "." || isOutsideRelative(fs, rel) || rel != name {
		return "", fmt.Errorf("copy: target %q is not a child of %q", target, root)
	}
	return target, nil
}
