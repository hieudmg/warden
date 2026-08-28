package sftp

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
)

// Copy copies source to destination. Files are staged in a unique sibling
// temporary file and renamed into place only after the source reader and the
// temporary writer have both closed. Directories are copied recursively,
// creating and chmodding every directory. Remote-to-remote copies are
// rejected when both endpoints identify the same configured host and port. A
// directory copy is also rejected when source and destination share an
// identity and the final target is the source or a descendant of it.
func Copy(source, destination Endpoint) error {
	sourceInfo, err := validateSource(source.FS, source.Path)
	if err != nil {
		return err
	}
	target, err := destinationPath(source, destination, sourceInfo)
	if err != nil {
		return err
	}
	if sourceInfo.IsDir() {
		// Same identity means source and destination share a namespace, so a
		// target inside the source tree would recurse forever. Check this
		// before the same-host rule so the more specific self-copy safeguard
		// remains in effect for two dials of one profile.
		if source.Identity == destination.Identity {
			if rel, relErr := source.FS.Rel(source.Path, target); relErr == nil &&
				(rel == "." || !isOutsideRelative(source.FS, rel)) {
				return fmt.Errorf("copy: refusing to copy directory %q into itself or a descendant (%q)", source.Path, target)
			}
		}
	}
	if source.HostIdentity != "" && source.HostIdentity == destination.HostIdentity {
		return fmt.Errorf("copy: refusing to copy between remote endpoints on same host %q", source.HostIdentity)
	}
	if sourceInfo.IsDir() {
		// A symlink in the destination path can redirect creation into the
		// source tree after the lexical self-copy check. Reject it before any
		// destination directory is created.
		if err := rejectSymlinkedDestination(destination.FS, target); err != nil {
			return err
		}
		return copyDirectory(source.FS, destination.FS, source.Path, target)
	}
	return copyFile(source.FS, destination.FS, source.Path, target, sourceInfo.Mode().Perm())
}

// destinationPath resolves the final target path for a copy. A directory
// source is placed under the destination when the destination exists as a
// directory, using the source's base name; otherwise the destination path is
// used as the target root (a missing destination becomes the copied root).
func destinationPath(source, destination Endpoint, sourceInfo os.FileInfo) (string, error) {
	if destInfo, err := destination.FS.Stat(destination.Path); err == nil && destInfo.IsDir() {
		return destination.FS.Join(destination.Path, source.FS.Base(source.Path)), nil
	}
	return destination.Path, nil
}

// isOutsideRelative reports whether rel leaves base through a parent path.
// A name such as "..child" is not a parent component and therefore remains
// inside the source tree; only an exact ".." or a separator-delimited parent
// prefix is outside.
func isOutsideRelative(fs Filesystem, rel string) bool {
	if rel == ".." {
		return true
	}
	parentPrefix := strings.TrimSuffix(fs.Join("..", "child"), "child")
	return parentPrefix != "" && strings.HasPrefix(rel, parentPrefix)
}

// rejectSymlinkedDestination checks every existing component of target with
// Lstat. This prevents a local symlink from redirecting recursive directory
// creation into the source tree. It is intentionally conservative for any
// filesystem adapter: an existing symlink component is never a safe recursive
// destination.
func rejectSymlinkedDestination(fs Filesystem, target string) error {
	for current := target; ; {
		if info, err := fs.Lstat(current); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("copy: destination path component %q is a symlink", current)
		}
		parent := fs.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

// validateSource verifies that name exists and is a regular file or
// directory. Symlinks and special files are rejected so the copy core never
// follows a link or duplicates a device, fifo, or socket.
func validateSource(fs Filesystem, name string) (os.FileInfo, error) {
	info, err := fs.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("copy: source %q: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("copy: source %q is a symlink; symlinks are not copied", name)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("copy: source %q is not a regular file or directory", name)
	}
	return info, nil
}

// copyFile copies one regular file into targetPath. Data is staged in a
// unique sibling temporary file so the destination is never observed in a
// partially written state. The rename happens only after the source reader,
// the temporary writer, and the mode change have all succeeded. Any error
// after the temporary file is created removes it before returning.
func copyFile(source, destination Filesystem, sourcePath, targetPath string, mode os.FileMode) error {
	if err := destination.MkdirAll(destination.Dir(targetPath), 0o755); err != nil {
		return err
	}
	reader, err := source.Open(sourcePath)
	if err != nil {
		return err
	}
	temp := temporarySibling(destination, targetPath)
	writer, err := destination.Create(temp)
	if err != nil {
		reader.Close()
		return err
	}
	_, copyErr := io.Copy(writer, reader)
	closeErr := reader.Close()
	if copyErr != nil {
		writer.Close()
		destination.Remove(temp)
		return copyErr
	}
	if closeErr != nil {
		writer.Close()
		destination.Remove(temp)
		return closeErr
	}
	if err := writer.Close(); err != nil {
		destination.Remove(temp)
		return err
	}
	if err := destination.Chmod(temp, mode); err != nil {
		destination.Remove(temp)
		return err
	}
	if err := destination.Rename(temp, targetPath); err != nil {
		destination.Remove(temp)
		return err
	}
	return nil
}

// copyDirectory recursively copies a directory tree, creating and chmodding
// every directory and copying regular files. Symlink and special children are
// rejected through validateSource.
func copyDirectory(source, destination Filesystem, sourceRoot, targetRoot string) error {
	if err := rejectSymlinkedDestination(destination, targetRoot); err != nil {
		return err
	}
	if err := destination.MkdirAll(targetRoot, 0o755); err != nil {
		return err
	}
	info, err := source.Stat(sourceRoot)
	if err != nil {
		return err
	}
	if err := destination.Chmod(targetRoot, info.Mode().Perm()); err != nil {
		return err
	}
	entries, err := source.ReadDir(sourceRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		sourcePath := source.Join(sourceRoot, name)
		targetPath := destination.Join(targetRoot, name)
		info, err := validateSource(source, sourcePath)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := copyDirectory(source, destination, sourcePath, targetPath); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(source, destination, sourcePath, targetPath, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

// temporarySibling returns a unique temporary path next to target so the
// final rename stays within one filesystem.
func temporarySibling(_ Filesystem, target string) string {
	var suffix [8]byte
	_, _ = rand.Read(suffix[:]) // crypto/rand.Read never returns an error
	return fmt.Sprintf("%s.warden-cp-%x", target, suffix)
}
