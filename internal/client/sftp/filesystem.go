// Package sftp provides endpoint-independent filesystem adapters for local
// paths and SFTP clients, plus recursive copy logic built on them.
package sftp

import (
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	pkgsftp "github.com/pkg/sftp"
)

// Filesystem abstracts the operations the copy core needs over a local
// directory tree or a remote SFTP session. Path operations use the
// platform-correct separator for the adapter: filepath for local, path for
// remote.
type Filesystem interface {
	Lstat(string) (os.FileInfo, error)
	Stat(string) (os.FileInfo, error)
	ReadDir(string) ([]os.FileInfo, error)
	Open(string) (io.ReadCloser, error)
	// Create exclusively creates staging: local 0600 (Windows owner-only DACL)
	// at creation, or remote handle chmod0600 before returning. Remote OPEN
	// cannot set creation permissions; see docs/security.md for the accepted
	// pre-chmod descriptor race. Errors never remove collisions.
	Create(string) (io.WriteCloser, error)
	MkdirAll(string, os.FileMode) error
	Chmod(string, os.FileMode) error
	Rename(string, string) error
	Remove(string) error
	Join(...string) string
	Dir(string) string
	Base(string) string
	Rel(string, string) (string, error)
	// CheckPath rejects symlink components in the original operand spelling,
	// before lexical cleaning can erase a link followed by a parent component.
	CheckPath(string) error
	// Clean is only lexical normalization for comparison/containment: native
	// local absolute paths, remote POSIX paths. Never replace a source operand
	// with its result; neither symlinks nor missing components are resolved.
	Clean(string) (string, error)
}

// Endpoint pairs a filesystem with a path on it. Identity distinguishes
// filesystems that share a namespace: local endpoints use the identity
// "local", and remote endpoints use the stable SSH connection ID of the
// dialed profile. HostIdentity identifies a remote host and port across
// profiles. Copy rejects a directory when source and destination identities
// match and the final target is the source or a descendant; it rejects any
// remote-to-remote copy whose host identities match.
type Endpoint struct {
	FS           Filesystem
	Path         string
	Identity     string
	HostIdentity string
}

type localFilesystem struct{}

// NewLocalFilesystem returns a Filesystem backed by the local OS.
func NewLocalFilesystem() Filesystem {
	return localFilesystem{}
}

func (localFilesystem) Lstat(p string) (os.FileInfo, error) { return os.Lstat(p) }
func (localFilesystem) Stat(p string) (os.FileInfo, error)  { return os.Stat(p) }

func (localFilesystem) ReadDir(p string) ([]os.FileInfo, error) {
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	infos := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (localFilesystem) Open(p string) (io.ReadCloser, error) { return os.Open(p) }
func (localFilesystem) Create(p string) (io.WriteCloser, error) {
	return createLocalStage(p)
}
func (localFilesystem) MkdirAll(p string, mode os.FileMode) error {
	return os.MkdirAll(p, mode)
}
func (localFilesystem) Chmod(p string, mode os.FileMode) error { return os.Chmod(p, mode) }
func (localFilesystem) Rename(oldname, newname string) error   { return os.Rename(oldname, newname) }
func (localFilesystem) Remove(p string) error                  { return os.Remove(p) }
func (localFilesystem) Join(elems ...string) string            { return filepath.Join(elems...) }
func (localFilesystem) Dir(p string) string                    { return filepath.Dir(p) }
func (localFilesystem) Base(p string) string                   { return filepath.Base(p) }
func (localFilesystem) Rel(base, target string) (string, error) {
	return filepath.Rel(base, target)
}

func (f localFilesystem) CheckPath(p string) error {
	separators := "/"
	if os.PathSeparator == '\\' {
		separators = `/\`
	}
	if !filepath.IsAbs(p) {
		// Resolve only the working directory/drive, not the operand's dot or
		// parent components. Join or Abs(p) here could erase a symlink first.
		volume := filepath.VolumeName(p)
		cwd, err := filepath.Abs(volume + ".")
		if err != nil {
			return err
		}
		tail := p[len(volume):]
		if len(tail) > 0 && strings.ContainsRune(separators, rune(tail[0])) {
			p = filepath.VolumeName(cwd) + tail // Native Windows rooted path.
		} else {
			p = cwd + string(os.PathSeparator) + tail
		}
	}
	return rejectSymlinkComponents(f, p, filepath.VolumeName(p), separators)
}

func (localFilesystem) Clean(p string) (string, error) { return filepath.Abs(p) }

type remoteFilesystem struct {
	client *pkgsftp.Client
}

// NewRemoteFilesystem returns a Filesystem backed by an SFTP client.
func NewRemoteFilesystem(client *pkgsftp.Client) Filesystem {
	return &remoteFilesystem{client: client}
}

func (r *remoteFilesystem) Lstat(p string) (os.FileInfo, error) { return r.client.Lstat(p) }
func (r *remoteFilesystem) Stat(p string) (os.FileInfo, error)  { return r.client.Stat(p) }
func (r *remoteFilesystem) ReadDir(p string) ([]os.FileInfo, error) {
	return r.client.ReadDir(p)
}
func (r *remoteFilesystem) Open(p string) (io.ReadCloser, error) { return r.client.Open(p) }
func (r *remoteFilesystem) Create(p string) (io.WriteCloser, error) {
	file, err := r.client.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return nil, err // No ownership: never remove a colliding file or symlink.
	}
	// File.Chmod uses FSETSTAT on this handle, not a path-based SETSTAT.
	// This deliberately does not claim privacy at OPEN (the public API has no
	// creation attributes). A pre-chmod open descriptor survives this change.
	if err := file.Chmod(0o600); err != nil {
		return nil, errors.Join(err, file.Close(), r.client.Remove(p))
	}
	return file, nil
}

// MkdirAll ignores mode because pkg/sftp's MkdirAll takes no mode; the copy
// core applies source mode bits through Chmod after creating each directory.
func (r *remoteFilesystem) MkdirAll(p string, _ os.FileMode) error {
	return r.client.MkdirAll(p)
}

func (r *remoteFilesystem) Chmod(p string, mode os.FileMode) error {
	return r.client.Chmod(p, mode)
}
func (r *remoteFilesystem) Rename(oldname, newname string) error {
	// Temporary file replacement needs the POSIX extension: SFTP v3 Rename
	// may reject an existing destination, while PosixRename provides the
	// overwrite semantics required by cp.
	return r.client.PosixRename(oldname, newname)
}
func (r *remoteFilesystem) Remove(p string) error { return r.client.Remove(p) }
func (r *remoteFilesystem) Join(elems ...string) string {
	return path.Join(elems...)
}
func (r *remoteFilesystem) Dir(p string) string  { return path.Dir(p) }
func (r *remoteFilesystem) Base(p string) string { return path.Base(p) }
func (r *remoteFilesystem) Rel(base, target string) (string, error) {
	return posixRel(base, target)
}
func (r *remoteFilesystem) CheckPath(p string) error {
	return rejectSymlinkComponents(r, p, "", "/")
}
func (r *remoteFilesystem) Clean(p string) (string, error) { return path.Clean(p), nil }

// posixRel returns a relative path from base to target using POSIX "/"
// separators, mirroring filepath.Rel for the remote (SFTP) namespace, which
// has no volume or case semantics.
func posixRel(basePath, targPath string) (string, error) {
	base := path.Clean(basePath)
	targ := path.Clean(targPath)
	if targ == base {
		return ".", nil
	}
	if base == "." {
		base = ""
	}
	baseSlashed := len(base) > 0 && base[0] == '/'
	targSlashed := len(targ) > 0 && targ[0] == '/'
	if baseSlashed != targSlashed {
		return "", errors.New("Rel: can't make " + targPath + " relative to " + basePath)
	}
	bl := len(base)
	tl := len(targ)
	var b0, bi, t0, ti int
	for {
		for bi < bl && base[bi] != '/' {
			bi++
		}
		for ti < tl && targ[ti] != '/' {
			ti++
		}
		if targ[t0:ti] != base[b0:bi] {
			break
		}
		if bi < bl {
			bi++
		}
		if ti < tl {
			ti++
		}
		b0 = bi
		t0 = ti
	}
	if base[b0:bi] == ".." {
		return "", errors.New("Rel: can't make " + targPath + " relative to " + basePath)
	}
	if b0 != bl {
		seps := strings.Count(base[b0:bl], "/")
		size := 2 + seps*3
		if tl != t0 {
			size += 1 + tl - t0
		}
		buf := make([]byte, size)
		n := copy(buf, "..")
		for i := 0; i < seps; i++ {
			buf[n] = '/'
			copy(buf[n+1:], "..")
			n += 3
		}
		if t0 != tl {
			buf[n] = '/'
			copy(buf[n+1:], targ[t0:])
		}
		// filepath.Rel retains a terminal dot component ("a" -> "." is
		// "../."). Cleaning here changes that contract, not containment.
		return string(buf), nil
	}
	return targ[t0:], nil
}
