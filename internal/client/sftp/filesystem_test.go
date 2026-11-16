package sftp

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

// Observe real client requests without constructing or modifying protocol frames.
// RequestServer loses OPEN's attribute flags when mapping requests; a stream
// observer also distinguishes handle FSETSTAT (10) from path SETSTAT (9).
type sftpWireObservation struct {
	kind         byte
	flags, attrs uint32
}
type observingSFTPConn struct {
	net.Conn
	mu                sync.Mutex
	pending           []byte
	packets           []sftpWireObservation
	beforeWrite       func()
	beforeHandleChmod func()
}

func (c *observingSFTPConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = append(c.pending, b[:n]...)
	for len(c.pending) >= 4 {
		size := int(binary.BigEndian.Uint32(c.pending[:4]))
		if len(c.pending) < 4+size {
			break
		}
		p := c.pending[4 : 4+size]
		event := sftpWireObservation{kind: p[0]}
		if p[0] == 3 && len(p) >= 9 {
			nameLen := int(binary.BigEndian.Uint32(p[5:9]))
			if len(p) >= 9+nameLen+8 {
				event.flags = binary.BigEndian.Uint32(p[9+nameLen:])
				event.attrs = binary.BigEndian.Uint32(p[13+nameLen:])
			}
		}
		if event.kind == 10 && c.beforeHandleChmod != nil {
			c.beforeHandleChmod()
		}
		if event.kind == 6 && c.beforeWrite != nil {
			c.beforeWrite()
		}
		c.packets = append(c.packets, event)
		c.pending = c.pending[4+size:]
	}
	return n, err
}
func (c *observingSFTPConn) snapshot() []sftpWireObservation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sftpWireObservation(nil), c.packets...)
}
func newAdapterSFTP(t *testing.T, root string) (Filesystem, *observingSFTPConn) {
	t.Helper()
	a, b := net.Pipe()
	observed := &observingSFTPConn{Conn: b}
	server, err := pkgsftp.NewServer(observed, pkgsftp.WithServerWorkingDirectory(root))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	client, err := pkgsftp.NewClientPipe(a, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close(); <-done })
	return NewRemoteFilesystem(client), observed
}

func TestPrivateExclusiveStagingBeforeFirstWrite(t *testing.T) {
	for _, adapter := range []string{"local", "actual-sftp"} {
		t.Run(adapter, func(t *testing.T) {
			root := t.TempDir()
			fs := NewLocalFilesystem()
			var observed *observingSFTPConn
			if adapter == "actual-sftp" {
				fs, observed = newAdapterSFTP(t, root)
			}
			name := filepath.Join(root, "stage")
			if observed != nil {
				observed.mu.Lock()
				observed.beforeHandleChmod = func() {
					info, err := os.Stat(name)
					if err != nil {
						t.Error(err)
						return
					}
					if info.Size() != 0 {
						t.Error("content exists before FSETSTAT")
					}
					t.Logf("remote initial mode before FSETSTAT=%#o; public creation window explicitly accepted", info.Mode().Perm())
				}
				observed.mu.Unlock()
			}
			w, err := fs.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			info, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Errorf("mode before any Write=%#o want0600", info.Mode().Perm())
			}
			if info.Size() != 0 {
				t.Fatal("prewrite stage nonempty")
			}
			if observed != nil {
				packets := observed.snapshot()
				openFound, handleMode := false, false
				for _, p := range packets {
					switch p.kind {
					case 3:
						openFound = true
						if p.flags != 2|8|32 {
							t.Errorf("OPEN flags=%#x want write/create/exclusive", p.flags)
						}
						t.Logf("OPEN attrs flags=%#x (no at-creation privacy claim)", p.attrs)
					case 10:
						handleMode = true
					case 9:
						t.Error("path SETSTAT used instead of handle FSETSTAT")
					case 6:
						t.Error("WRITE before Create returned")
					}
				}
				if !openFound || !handleMode {
					t.Errorf("missing exclusive OPEN or FSETSTAT: %v", packets)
				}
				observed.mu.Lock()
				observed.beforeWrite = func() {
					info, e := os.Stat(name)
					if e != nil {
						t.Error(e)
						return
					}
					if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
						t.Errorf("mode at WRITE=%#o", info.Mode().Perm())
					}
				}
				observed.mu.Unlock()
			}
			if _, err := w.Write([]byte("synthetic content")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExclusiveStagingCollisionsPreserveExisting(t *testing.T) {
	for _, adapter := range []string{"local", "actual-sftp"} {
		t.Run(adapter, func(t *testing.T) {
			root := t.TempDir()
			fs := NewLocalFilesystem()
			if adapter == "actual-sftp" {
				fs, _ = newAdapterSFTP(t, root)
			}
			original := filepath.Join(root, "old")
			if err := os.WriteFile(original, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"file", "symlink"} {
				t.Run(kind, func(t *testing.T) {
					name := original
					if kind == "symlink" {
						name = filepath.Join(root, "link")
						if err := os.Symlink(original, name); err != nil {
							t.Skipf("symlink unavailable: %v", err)
						}
					}
					w, err := fs.Create(name)
					if err == nil {
						w.Close()
						t.Error("collision accepted")
					}
					info, err := os.Lstat(name)
					if err != nil {
						t.Fatalf("collision removed: %v", err)
					}
					if kind == "symlink" && info.Mode()&os.ModeSymlink == 0 {
						t.Error("symlink replaced")
					}
					data, err := os.ReadFile(original)
					if err != nil || string(data) != "preserve" {
						t.Fatalf("collision data=%q err=%v", data, err)
					}
				})
			}
		})
	}
}

type rejectStageChmod struct {
	root                    string
	writes, closed, removed int
	chmodErr                error
}

func (h *rejectStageChmod) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	flags := r.Pflags()
	f := os.O_CREATE | os.O_WRONLY
	if flags.Excl {
		f |= os.O_EXCL
	}
	if flags.Trunc {
		f |= os.O_TRUNC
	}
	file, err := os.OpenFile(filepath.Join(h.root, "stage"), f, 0644)
	if err != nil {
		return nil, err
	}
	return &stageWriteObserver{h, file}, nil
}

type stageWriteObserver struct {
	h *rejectStageChmod
	*os.File
}

func (w *stageWriteObserver) WriteAt(b []byte, off int64) (int, error) {
	w.h.writes++
	return w.File.WriteAt(b, off)
}
func (w *stageWriteObserver) Close() error { w.h.closed++; return w.File.Close() }
func (h *rejectStageChmod) Filecmd(r *pkgsftp.Request) error {
	if r.Method == "Remove" {
		h.removed++
		return os.Remove(filepath.Join(h.root, "stage"))
	}
	return h.chmodErr
}
func TestRemoteUnsupportedStagingChmodFailsBeforeWrite(t *testing.T) {
	for _, chmodErr := range []error{pkgsftp.ErrSSHFxOpUnsupported, os.ErrPermission} {
		t.Run(chmodErr.Error(), func(t *testing.T) {
			a, b := net.Pipe()
			h := &rejectStageChmod{root: t.TempDir(), chmodErr: chmodErr}
			server := pkgsftp.NewRequestServer(b, pkgsftp.Handlers{FilePut: h, FileCmd: h})
			done := make(chan error, 1)
			go func() { done <- server.Serve() }()
			client, err := pkgsftp.NewClientPipe(a, a)
			if err != nil {
				t.Fatal(err)
			}
			fs := NewRemoteFilesystem(client)
			w, err := fs.Create("stage")
			if err == nil {
				w.Write([]byte("must not write"))
				w.Close()
				t.Error("unsupported chmod accepted")
			}
			client.Close()
			server.Close()
			<-done
			if h.writes != 0 || h.closed != 1 || h.removed != 1 {
				t.Errorf("writes=%d closes=%d removes=%d", h.writes, h.closed, h.removed)
			}
			if _, err := os.Stat(filepath.Join(h.root, "stage")); !os.IsNotExist(err) {
				t.Errorf("owned stage not cleaned: %v", err)
			}
		})
	}
}
