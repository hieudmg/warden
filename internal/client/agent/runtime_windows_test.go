//go:build windows

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// These are native Windows security tests. Cross-compilation is NOT evidence
// that named-pipe/NTFS ACL enforcement or reparse-point behavior passed.
func TestRuntimeWindowsReaderBlocksStagingUnlink(t *testing.T) {
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "a"))
	reader, _ := NewRuntimeAt(runtime.dir)
	originalRemove := removeCredentialStage
	defer func() { removeCredentialStage = originalRemove; runtime.Cleanup() }()
	var stage string
	var removeErr error
	removals := 0
	removeCredentialStage = func(directory *privateDirectory, name string) error {
		removals++
		stage = name
		path, err := windows.UTF16PtrFromString(filepath.Join(runtime.dir, name))
		if err != nil {
			return err
		}
		// Hold the same read/share rights as openPrivateChild, at its
		// post-open/pre-validation scheduling point. Production immediately
		// rejects this two-link file; the fixture deliberately keeps it open.
		handle, err := windows.CreateFile(path, windows.FILE_GENERIC_READ|windows.READ_CONTROL,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(handle)
		if _, err := reader.ReadToken(); err == nil {
			return errors.New("reader accepted multiply-linked publication")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, token, err := reader.connect(ctx)
		if conn != nil {
			conn.Close()
		}
		if err == nil || len(token) != 0 {
			return errors.New("attachment consumed incomplete publication")
		}
		// Microsoft CreateFile share semantics + Go1.25 Deleteat's DELETE
		// open predict a sharing violation, not a successful unlink. Execute
		// this on Windows/NTFS: cross-compilation cannot verify that outcome.
		removeErr = originalRemove(directory, name)
		return removeErr
	}
	_, err := runtime.Listen()
	if !errors.Is(removeErr, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("native staging removal = %v; startup = %v; want sharing violation", removeErr, err)
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("Listen = %v; want native unlink failure, not readiness", err)
	}
	if removals != 1 {
		t.Fatalf("retried ambiguous native staging removal %d times", removals)
	}
	if err := runtime.Cleanup(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{runtimeToken, stage} {
		if _, err := os.Stat(filepath.Join(runtime.dir, name)); err != nil {
			t.Fatal("lost ambiguous native publication", name, err)
		}
	}
	if _, err := reader.ReadToken(); err == nil {
		t.Fatal("accepted failed native publication")
	}
}

func TestPipeSquatterCannotCollectSecrets(t *testing.T) {
	TestAgentAuthenticatesServerBeforeSecretBytes(t)
}

func setRuntimeTestSD(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeACLProtectsNamedPipe(t *testing.T) {
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "a"))
	listener, err := runtime.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Cleanup()
	checked := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			checked <- err
			return
		}
		raw := conn.(*tls.Conn).NetConn()
		defer raw.Close()
		// Exact winio0.6.2 win32File.Fd exposes the accepted server handle.
		handle := windows.Handle(raw.(interface{ Fd() uintptr }).Fd())
		// Microsoft documents pipes as kernel objects; GetSecurityInfo supports
		// their owner/DACL using the ordinary READ_CONTROL access (no SACL).
		sd, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err == nil {
			err = validateRuntimeSecurityDescriptor(sd)
		}
		checked <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Security fixture only: establish the native pipe without sending any
	// token/application bytes, then inspect the actual server-side descriptor.
	conn, err := dialRuntime(ctx, runtime.EndpointPath())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case err := <-checked:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("pipe ACL inspection timed out")
	}
}

func TestRuntimeACLRejectsOtherUser(t *testing.T) {
	for _, target := range []string{"directory", "credential"} {
		t.Run(target, func(t *testing.T) {
			runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "a"))
			if _, err := runtime.Listen(); err != nil {
				t.Fatal(err)
			}
			defer runtime.Cleanup()
			good, err := runtimeSDDL()
			if err != nil {
				t.Fatal(err)
			}
			sid, err := currentUserSID()
			if err != nil {
				t.Fatal(err)
			}
			path := runtime.dir
			if target == "credential" {
				path = runtime.tokenPath()
			}
			setRuntimeTestSD(t, path, "O:"+sid.String()+"D:P(A;;FA;;;"+sid.String()+")(A;;GR;;;WD)")
			defer setRuntimeTestSD(t, path, good)
			if _, err := runtime.ReadToken(); err == nil {
				t.Fatal("other-principal read ACE accepted for runtime trust")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, _, err := tryRuntime(ctx, runtime); err == nil {
				conn.Close()
				t.Fatal("client used untrusted certificate file ACL")
			}
		})
	}
	// Owner substitution cannot be manufactured by an ordinary user on NTFS.
	// This real Windows descriptor fixture separately checks the owner predicate.
	sd, err := windows.SecurityDescriptorFromString("O:SYD:P(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRuntimeSecurityDescriptor(sd); err == nil {
		t.Fatal("wrong descriptor owner accepted")
	}
}

func TestRuntimeWindowsReparseAndReconnect(t *testing.T) {
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "a"))
	if _, err := runtime.Listen(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Cleanup()
	original, err := os.ReadFile(runtime.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openPrivateDirectory(runtime.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.root.Remove(runtimeToken); err != nil {
		directory.Close()
		t.Fatal(err)
	}
	target := filepath.Join(runtime.dir, "target")
	file, err := openPrivateChild(directory.file, "target", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		directory.Close()
		t.Fatal(err)
	}
	_, err = file.Write(original)
	file.Close()
	directory.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, runtime.tokenPath()); err != nil {
		// Restoring valid discovery also ensures fixture cleanup is meaningful.
		_ = rewritePrivateDiscovery(runtime, original)
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skip("native symlink fixture needs Developer Mode or symlink privilege")
		}
		t.Fatal(err)
	}
	if _, err := runtime.ReadToken(); err == nil {
		t.Fatal("accepted reparse trust path")
	}
	if err := rewritePrivateDiscovery(runtime, original); err != nil {
		t.Fatal(err)
	}
	restored, err := runtime.ReadToken()
	if err != nil {
		t.Fatal(err)
	}
	var record runtimeCredentials
	directory, err = openPrivateDirectory(runtime.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	current, err := readCredentials(directory)
	directory.Close()
	if err != nil {
		t.Fatal(err)
	}
	record = *current
	if !bytes.Equal(restored, record.Token) {
		t.Fatal("restored IPC token changed")
	}
	server, err := NewRuntimeServer(runtime, NewDefaultPool(time.Now, 10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	conn, err := runtime.Dial(ctx)
	if err != nil {
		t.Fatal("legitimate reconnect failed", err)
	}
	conn.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("native reconnect cleanup hung")
	}
}
