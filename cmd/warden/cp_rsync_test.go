package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"

	"warden/internal/client/agent"
	clientssh "warden/internal/client/ssh"
	"warden/internal/model"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && (os.Args[1] == agent.RsyncHelperCommand || os.Args[1] == "cp") {
		main()
	}
	os.Exit(m.Run())
}

func TestRunCPRsyncEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX remote shell")
	}
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("remote fixture needs stock rsync")
	}
	remote := newCLITestSSHServer(t, "s3cret")
	runCP, _ := startCPEndToEndFixture(t, remote, newCLITestSSHServer(t, "s3cret"))
	local := t.TempDir()
	source := filepath.Join(local, "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	remoteName := "-literal ' \" $ [abc]*? `name` \\ \xff\n"
	const file = "child [xy]; echo"
	const rawFile = "regular\xff"
	writeCPFile(t, filepath.Join(source, file), "new")
	writeCPFile(t, filepath.Join(source, rawFile), "literal filename")
	copy := func(src, dst string) {
		t.Helper()
		out, stderr, status := runCP("cp", "--backend=rsync", src, dst)
		if status != 0 || out != "" || stderr != "" {
			t.Fatalf("cp %q => %q: status=%d stdout=%q stderr=%q", src, dst, status, out, stderr)
		}
	}
	t.Chdir(local)
	copy("source", "source:missing/parents/"+remoteName)
	remoteName = "missing/parents/" + remoteName
	remoteRoot := filepath.Join(remote.root, remoteName)
	assertCLILocalFile(t, filepath.Join(remoteRoot, file), "new", 0o600)
	assertCLILocalFile(t, filepath.Join(remoteRoot, rawFile), "literal filename", 0o600)

	// A regular destination basis must not skip different bytes even when size and mtime match.
	writeCPFile(t, filepath.Join(remoteRoot, "source", file), "old")
	writeCPFile(t, filepath.Join(remoteRoot, "source", "unrelated"), "keep")
	mtime := time.Unix(1_700_000_000, 0)
	for _, name := range []string{filepath.Join(source, file), filepath.Join(remoteRoot, "source", file)} {
		if err := os.Chtimes(name, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	writeCPFile(t, filepath.Join(source, "type-change", "child"), "inside")
	writeCPFile(t, filepath.Join(remoteRoot, "source", "type-change"), "old file")
	copy(source+"/", "source:"+remoteName)
	assertCLILocalFile(t, filepath.Join(remoteRoot, "source", file), "new", 0o600)
	assertCLILocalFile(t, filepath.Join(remoteRoot, "source", "type-change", "child"), "inside", 0o600)
	assertCLILocalFile(t, filepath.Join(remoteRoot, "source", "unrelated"), "keep", 0o600)

	if err := os.Mkdir(filepath.Join(local, "download"), 0o755); err != nil {
		t.Fatal(err)
	}
	copy("source:"+remoteName+"/", filepath.Join(local, "download"))
	assertCLILocalFile(t, filepath.Join(local, "download", filepath.Base(remoteName), file), "new", 0o600)
	assertCLILocalFile(t, filepath.Join(local, "download", filepath.Base(remoteName), rawFile), "literal filename", 0o600)
	copy("source:"+remoteName, filepath.Join(local, "missing", "parents", "renamed\xff"))
	assertCLILocalFile(t, filepath.Join(local, "missing", "parents", "renamed\xff", file), "new", 0o600)

	localBasis := filepath.Join(local, "download", filepath.Base(remoteName), file)
	writeCPFile(t, localBasis, "old")
	for _, name := range []string{filepath.Join(remoteRoot, file), localBasis} {
		if err := os.Chtimes(name, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	copy("source:"+remoteName, filepath.Join(local, "download"))
	assertCLILocalFile(t, localBasis, "new", 0o600)
	if remote.execs.Load() < 5 {
		t.Fatal("explicit directory rsync did not use remote exec for all transfers")
	}
}

func TestRunCPRsyncRegularFilesRouteDirectlyToSFTP(t *testing.T) {
	remote := newCLITestSSHServer(t, "s3cret", func(s *cliTestSSHServer) { s.execEnv = []string{"PATH="} })
	runCP, _ := startCPEndToEndFixture(t, remote, newCLITestSSHServer(t, "s3cret"))
	local := t.TempDir()
	writeCPFile(t, filepath.Join(local, "upload"), "upload bytes")
	writeCPFile(t, filepath.Join(remote.root, "download"), "download bytes")
	for _, tc := range [][2]string{
		{filepath.Join(local, "upload"), "source:renamed-upload"},
		{"source:download", filepath.Join(local, "renamed-download")},
		{filepath.Join(local, "upload"), "source:."},
	} {
		if out, stderr, status := runCP("cp", "--backend=rsync", tc[0], tc[1]); status != 0 || out != "" || stderr != "" {
			t.Fatalf("cp %q => %q: status=%d stdout=%q stderr=%q", tc[0], tc[1], status, out, stderr)
		}
	}
	assertCLILocalFile(t, filepath.Join(remote.root, "renamed-upload"), "upload bytes", 0o600)
	assertCLILocalFile(t, filepath.Join(remote.root, "upload"), "upload bytes", 0o600)
	assertCLILocalFile(t, filepath.Join(local, "renamed-download"), "download bytes", 0o600)
	if remote.execs.Load() != 0 {
		t.Fatal("regular files must route to SFTP before remote rsync probing or execution")
	}
}

func TestRunCPRsyncRejectsUnsafeOperandsBeforeExec(t *testing.T) {
	remote := newCLITestSSHServer(t, "s3cret")
	dst := newCLITestSSHServer(t, "s3cret")
	runCP, _ := startCPEndToEndFixture(t, remote, dst)
	local := t.TempDir()
	writeCPFile(t, filepath.Join(remote.root, "existing-file"), "keep")
	writeCPFile(t, filepath.Join(local, "existing-file"), "keep")
	cleanTree := filepath.Join(local, "clean-tree")
	writeCPFile(t, filepath.Join(cleanTree, "payload"), "new")
	writeCPFile(t, filepath.Join(remote.root, "remote-tree", "payload"), "new")
	writeCPFile(t, filepath.Join(local, "existing", "symlink-target"), "keep")
	writeCPFile(t, filepath.Join(remote.root, "symlink-target"), "keep")
	if err := os.MkdirAll(filepath.Join(remote.root, "merge", "clean-tree"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(local, "existing", "remote-tree"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(local, "source-link")
	if err := os.Symlink(local, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, pair := range [][2]string{
		{filepath.Join(remote.root, "symlink-target"), filepath.Join(remote.root, "merge", "clean-tree", "payload")},
		{filepath.Join(local, "existing", "symlink-target"), filepath.Join(local, "existing", "remote-tree", "payload")},
	} {
		if err := os.Symlink(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ src, dst, diagnostic string }{
		{cleanTree, "source:merge", "symlink"},
		{"source:remote-tree", filepath.Join(local, "existing"), "symlink"},
		{local, "source:untouched", "symlink"},
		{local, "source:existing-file", "directory"},
		{"source:.", filepath.Join(local, "existing-file"), "directory"},
		{"source:..", filepath.Join(local, "existing"), "unsafe destination child"},
		{link + "/", "source:untouched", "symlink"},
		{link + "/../" + filepath.Base(local), "source:untouched", "symlink"},
		{filepath.Join(local, "missing"), "source:untouched", "source"},
		{"source:.", "destination:untouched", "remote-to-remote"},
	} {
		if _, stderr, status := runCP("cp", "--backend=rsync", tc.src, tc.dst); status == 0 || !strings.Contains(stderr, tc.diagnostic) {
			t.Errorf("cp %q => %q: status=%d stderr=%q; want failure mentioning %q", tc.src, tc.dst, status, stderr, tc.diagnostic)
		}
	}
	assertCLILocalFile(t, filepath.Join(remote.root, "existing-file"), "keep", 0o600)
	assertCLILocalFile(t, filepath.Join(local, "existing-file"), "keep", 0o600)
	assertCLILocalFile(t, filepath.Join(local, "existing", "symlink-target"), "keep", 0o600)
	assertCLILocalFile(t, filepath.Join(remote.root, "symlink-target"), "keep", 0o600)
	if remote.execs.Load()+dst.execs.Load() != 0 {
		t.Fatal("unsafe operands started remote execution")
	}
	if _, err := os.Lstat(filepath.Join(remote.root, "untouched")); !os.IsNotExist(err) {
		t.Fatalf("unexpected destination change: %v", err)
	}
}

func TestRunCPRsyncRejectsSpecialFilesBeforeExec(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixture uses Linux Unix-domain socket files")
	}
	remote := newCLITestSSHServer(t, "s3cret")
	runCP, _ := startCPEndToEndFixture(t, remote, newCLITestSSHServer(t, "s3cret"))
	local := t.TempDir()
	for _, root := range []string{local, remote.root} {
		listener, err := net.Listen("unix", filepath.Join(root, "socket"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
	}
	for _, tc := range []struct{ source, destination, diagnostic string }{
		{filepath.Join(local, "socket"), "source:untouched", "regular file or directory"},
		{local, "source:untouched", "special file"},
		{"source:socket", filepath.Join(local, "untouched"), "regular file or directory"},
		{"source:.", filepath.Join(local, "untouched"), "special file"},
	} {
		if _, stderr, status := runCP("cp", "--backend=rsync", tc.source, tc.destination); status == 0 || !strings.Contains(stderr, tc.diagnostic) {
			t.Errorf("cp %q => %q: status=%d stderr=%q; want failure mentioning %q", tc.source, tc.destination, status, stderr, tc.diagnostic)
		}
	}
	if remote.execs.Load() != 0 {
		t.Fatal("special source started remote execution")
	}
	for _, root := range []string{local, remote.root} {
		if _, err := os.Lstat(filepath.Join(root, "untouched")); !os.IsNotExist(err) {
			t.Fatalf("unexpected destination change: %v", err)
		}
	}
}

func TestRunCPRsyncMissingRemoteDoesNotFallBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX remote shell")
	}
	remote := newCLITestSSHServer(t, "s3cret", func(s *cliTestSSHServer) { s.execEnv = []string{"PATH="} })
	runCP, _ := startCPEndToEndFixture(t, remote, newCLITestSSHServer(t, "s3cret"))
	local := t.TempDir()
	writeCPFile(t, filepath.Join(local, "payload"), "new")
	if _, stderr, status := runCP("cp", "--backend=rsync", local, "source:untouched"); status == 0 || !strings.Contains(stderr, "remote rsync") {
		t.Fatalf("missing remote rsync: status=%d stderr=%q", status, stderr)
	}
	if _, err := os.Lstat(filepath.Join(remote.root, "untouched")); !os.IsNotExist(err) {
		t.Fatalf("unexpected destination change: %v", err)
	}
}

func TestRunCPRsyncRemoteFailureDoesNotFallBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX remote shell")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "rsync"), []byte("#!/bin/sh\nexit 23\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	remote := newCLITestSSHServer(t, "s3cret", func(s *cliTestSSHServer) {
		s.execEnv = []string{"PATH=" + bin + ":" + os.Getenv("PATH")}
	})
	runCP, _ := startCPEndToEndFixture(t, remote, newCLITestSSHServer(t, "s3cret"))
	local := t.TempDir()
	source := filepath.Join(local, "tree")
	writeCPFile(t, filepath.Join(source, "payload"), "new")
	target := filepath.Join(remote.root, "merge", "tree", "payload")
	writeCPFile(t, target, "keep")
	if _, stderr, status := runCP("cp", "--backend=rsync", source, "source:merge"); status == 0 || !strings.Contains(stderr, "remote rsync failed") {
		t.Fatalf("failed remote rsync: status=%d stderr=%q", status, stderr)
	}
	if remote.execs.Load() != 2 {
		t.Fatalf("wanted remote availability check and transfer attempt, execs=%d", remote.execs.Load())
	}
	assertCLILocalFile(t, target, "keep", 0o600)
}

func TestRunCPRsyncRejectsMismatchedHostKey(t *testing.T) {
	remote := newCLITestSSHServer(t, "s3cret")
	other := newCLITestSSHServer(t, "s3cret")
	runCP, _ := startCPEndToEndFixture(t, remote, other)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(knownhosts.Line([]string{remote.addr}, other.hostKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := t.TempDir()
	writeCPFile(t, filepath.Join(local, "payload"), "new")
	if _, stderr, status := runCP("cp", "--backend=rsync", local, "source:untouched"); status == 0 || !strings.Contains(strings.ToLower(stderr), "host key") {
		t.Fatalf("mismatched SSH host key: status=%d stderr=%q", status, stderr)
	}
	if remote.execs.Load() != 0 {
		t.Fatal("mismatched host key started remote command")
	}
	if _, err := os.Lstat(filepath.Join(remote.root, "untouched")); !os.IsNotExist(err) {
		t.Fatalf("unexpected destination change: %v", err)
	}
}

func TestRunCPRsyncRejectsNonUTF8UploadDirectoryBeforeWrites(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixture uses Linux filenames and a POSIX SSH peer")
	}
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("remote fixture needs stock rsync")
	}
	remote := newCLITestSSHServer(t, "s3cret")
	runCP, _ := startCPEndToEndFixture(t, remote, newCLITestSSHServer(t, "s3cret"))
	source := filepath.Join(t.TempDir(), "tree")
	writeCPFile(t, filepath.Join(source, "valid", "nested\xff", "payload"), "must not be skipped")
	writeCPFile(t, filepath.Join(source, "plain"), "new")
	prior := filepath.Join(remote.root, "existing", "tree", "plain")
	writeCPFile(t, prior, "old")
	for _, dest := range []string{"missing", "existing"} {
		if _, stderr, status := runCP("cp", "--backend=rsync", source, "source:"+dest); status == 0 || !strings.Contains(stderr, "UTF-8") {
			t.Errorf("non-UTF-8 directory => %s: status=%d stderr=%q", dest, status, stderr)
		}
	}
	if remote.execs.Load() != 0 {
		t.Error("unsafe source reached remote execution")
	}
	if _, err := os.Lstat(filepath.Join(remote.root, "missing")); !os.IsNotExist(err) {
		t.Errorf("unexpected destination change: %v", err)
	}
	assertCLILocalFile(t, prior, "old", 0o600)
}

func TestRunCPRsyncStalledCancelPreservesActiveSSH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX remote shell")
	}
	var stallNext atomic.Bool
	stalled := make(chan (<-chan struct{}), 1)
	remote := newCLITestSSHServer(t, "s3cret", func(s *cliTestSSHServer) {
		s.stallSession = func(done <-chan struct{}) bool {
			if !stallNext.CompareAndSwap(true, false) {
				return false
			}
			stalled <- done
			return true
		}
	})
	startCPEndToEndFixture(t, remote, newCLITestSSHServer(t, "s3cret"))
	host, portString, err := net.SplitHostPort(remote.addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	bundle := model.SSHBundle{Target: model.SSHNode{ID: 1, Name: "source", Host: host, Port: port, Username: "user", Password: []byte("s3cret")}}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	in, send := io.Pipe()
	defer in.Close()
	defer send.Close()
	output, out := io.Pipe()
	defer output.Close()
	defer out.Close()
	sshDone := make(chan error, 1)
	go func() {
		sshDone <- agent.RunSSH(ctx, bundle, `printf ready; read line; printf '%s' "$line"`, clientssh.Streams{Stdin: in, Stdout: out})
		_ = out.Close()
	}()
	read := func(want string) {
		t.Helper()
		got := make([]byte, len(want))
		done := make(chan error, 1)
		go func() { _, err := io.ReadFull(output, got); done <- err }()
		select {
		case err := <-done:
			if err != nil || string(got) != want {
				t.Fatalf("active SSH output = %q, %v; want %q", got, err, want)
			}
		case <-ctx.Done():
			t.Fatalf("waiting for active SSH output %q: %v", want, ctx.Err())
		}
	}
	read("ready") // the held command already owns a pooled lease

	stallNext.Store(true)
	copyCtx, cancelCopy := context.WithCancel(ctx)
	defer cancelCopy()
	copyDone := make(chan error, 1)
	source := t.TempDir()
	go func() {
		copyDone <- agent.RunCopyRequest(copyCtx, agent.CopyRequest{Backend: agent.CopyRsync,
			Source: agent.CopyEndpoint{Path: source}, Destination: agent.CopyEndpoint{Bundle: &bundle, Path: "untouched"}})
	}()
	select {
	case done := <-stalled:
		cancelCopy()
		select {
		case <-done: // require the agent to release the stalled connection, not just the CLI
		case <-ctx.Done():
			t.Fatal("cancel did not close the stalled copy transport")
		}
	case <-ctx.Done():
		t.Fatal("copy session never reached the stalled channel-open request")
	}
	if err := <-copyDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("stalled copy returned %v; want canceled", err)
	}
	go func() { _, _ = io.WriteString(send, "still-active\n"); _ = send.Close() }()
	read("still-active")
	select {
	case err := <-sshDone:
		if err != nil {
			t.Fatalf("unrelated SSH command failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("unrelated SSH command did not complete")
	}
	if _, err := os.Lstat(filepath.Join(remote.root, "untouched")); !os.IsNotExist(err) {
		t.Fatalf("unexpected destination change: %v", err)
	}
}

func TestRunCPRsyncInterruptPreservesExistingFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixture interrupts the Linux CLI with SIGINT")
	}
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("remote fixture needs stock rsync")
	}
	for _, upload := range []bool{false, true} {
		name := "download"
		if upload {
			name = "upload"
		}
		t.Run(name, func(t *testing.T) {
			remote := newCLITestSSHServer(t, "s3cret", func(s *cliTestSSHServer) { s.execThrottle = 4 * time.Millisecond })
			_, stopAgent := startCPEndToEndFixture(t, remote, newCLITestSSHServer(t, "s3cret"))
			local := t.TempDir()
			remotePayload := filepath.Join(remote.root, "tree", "payload")
			localPayload := filepath.Join(local, "tree", "payload")
			dest, src := localPayload, remotePayload
			args := []string{"source:tree", local}
			if upload {
				dest, src = remotePayload, localPayload
				args = []string{filepath.Dir(localPayload), "source:."}
			}
			writeCPFile(t, dest, "original bytes")
			if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
				t.Fatal(err)
			}
			const dataSize = 12 << 20
			if err := os.WriteFile(src, bytes.Repeat([]byte{'N'}, dataSize), 0o600); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "cp", "--backend=rsync", args[0], args[1])
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			finished := make(chan error, 1)
			go func() { finished <- cmd.Wait() }()
			var partial string
			deadline := time.After(6 * time.Second)
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
		waitPartial:
			for {
				select {
				case err := <-finished:
					t.Fatalf("transfer ended before interruption: %v, stderr=%q", err, stderr.String())
				case <-deadline:
					break waitPartial
				case <-ticker.C:
					matches, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".payload*"))
					for _, match := range matches {
						if st, err := os.Stat(match); err == nil && st.Size() > 0 && st.Size() < dataSize {
							partial = match
							break waitPartial
						}
					}
				}
			}
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-finished:
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 || !strings.Contains(stderr.String(), "context canceled") {
					t.Fatalf("interrupted copy: %v, stderr=%q", err, stderr.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("interrupted CLI did not return")
			}
			if partial == "" {
				t.Fatal("did not observe an incomplete staging file")
			}
			for deadline := time.Now().Add(4 * time.Second); ; {
				if _, err := os.Lstat(partial); os.IsNotExist(err) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("rsync left partial file %q", partial)
				}
				time.Sleep(10 * time.Millisecond)
			}
			assertCLILocalFile(t, dest, "original bytes", 0o600)
			stopAgent()
			waitForCLIConnectionsClosed(t, remote)
		})
	}
}

func writeCPFile(t *testing.T, name, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
