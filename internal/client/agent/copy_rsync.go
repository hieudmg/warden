package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/gokrazy/rsync/rsyncclient"
	"golang.org/x/crypto/ssh"

	"warden/internal/client/sftp"
	clientssh "warden/internal/client/ssh"
)

func copyRsyncRequest(ctx context.Context, pool *Pool, req CopyRequest) error {
	sourceBundle, destinationBundle := endpointBundle(req.Source), endpointBundle(req.Destination)
	if (sourceBundle == nil) == (destinationBundle == nil) {
		return errors.New("rsync requires one local and one remote endpoint")
	}
	upload := sourceBundle == nil
	bundle := sourceBundle
	if upload {
		bundle = destinationBundle
	}
	// Even SFTP metadata can stall before SSH creates a channel to close.
	// Own a transport from the beginning so abort never touches pooled leases.
	graph, release, err := pool.dialExclusive(ctx, *bundle)
	if err != nil {
		return err
	}
	stop := watchRsyncCancel(ctx, graph)
	defer stop()
	defer release()
	peer := graph.Target()
	source, sourceRemote, err := openCopyEndpoint(req.Source, peer)
	if err != nil {
		return err
	}
	if sourceRemote != nil {
		defer sourceRemote.Close()
	}
	destination, destinationRemote, err := openCopyEndpoint(req.Destination, peer)
	if err != nil {
		return err
	}
	if destinationRemote != nil {
		defer destinationRemote.Close()
	}
	remote := sourceRemote
	if upload {
		remote = destinationRemote
	}
	return copyRsync(ctx, source, destination, remote, peer, upload)
}

func copyRsync(ctx context.Context, source, destination sftp.Endpoint, remote *sftp.Remote, peer *ssh.Client, upload bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sourceOriginal, destinationOriginal := source, destination

	var err error
	if !upload {
		source.Path, err = absoluteRemoteRsyncPath(remote, source.Path)
		if err != nil {
			return err
		}
	}
	srcInfo, err := inspectRsyncPath(source, !upload, false)
	if err != nil {
		return fmt.Errorf("rsync: source %q: %w", sourceOriginal.Path, err)
	}
	if srcInfo.Mode().IsRegular() {
		// Initial routing only: preserve the existing SFTP destination and
		// explicit-filename behavior, without starting a remote command.
		if upload {
			sourceOriginal.Path = sourceOriginal.FS.Join(sourceOriginal.Path)
		} else {
			destinationOriginal.Path = destinationOriginal.FS.Join(destinationOriginal.Path)
		}
		return copySFTP(sourceOriginal, destinationOriginal)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("rsync: source %q is not a regular file or directory", sourceOriginal.Path)
	}
	if upload {
		destination.Path, err = absoluteRemoteRsyncPath(remote, destination.Path)
		if err != nil {
			return err
		}
	}
	dstInfo, err := inspectRsyncPath(destination, upload, true)
	if err != nil {
		return fmt.Errorf("rsync: destination %q: %w", destinationOriginal.Path, err)
	}
	source.Path = source.FS.Join(source.Path) // validated raw components above
	destination.Path = destination.FS.Join(destination.Path)
	policy := rsyncTreePolicy{goSender: upload, windowsDestination: !upload && runtime.GOOS == "windows"}
	if dstInfo != nil {
		if !dstInfo.IsDir() {
			return fmt.Errorf("rsync: destination %q must be a directory", destinationOriginal.Path)
		}
		base := "."
		if !upload {
			base = sourceOriginal.FS.Base(sourceOriginal.Path)
		} else if source.FS.Dir(source.Path) != source.Path {
			base = source.FS.Base(source.Path)
		}
		// Explicit dot and root operands have no child name.
		if base != "." && base != "/" {
			if err := validateRsyncChild(base, policy.windowsDestination); err != nil {
				return fmt.Errorf("rsync: unsafe destination child: %w", err)
			}
			parent := destination
			destination.Path = destination.FS.Join(destination.Path, base)
			dstInfo, err = inspectRsyncPath(destination, upload, true)
			if err != nil {
				return fmt.Errorf("rsync: destination %q: %w", destination.Path, err)
			}
			if dstInfo != nil && !dstInfo.IsDir() {
				return fmt.Errorf("rsync: destination %q must be a directory", destination.Path)
			}
			if policy.windowsDestination && dstInfo != nil {
				names, err := readWindowsRsyncNames(parent)
				if err != nil {
					return err
				}
				if names.match(base) == "" {
					return fmt.Errorf("rsync: destination %q resolves through an unlisted Windows alias", destination.Path)
				}
			}
		}
	}
	if err := checkRsyncTree(ctx, source, destination, dstInfo != nil, policy); err != nil {
		return fmt.Errorf("rsync: %w", err)
	}
	if err := checkRemoteRsync(ctx, peer); err != nil {
		return err
	}
	if upload {
		prefix, err := rsyncRemoteDirectory(destination, dstInfo == nil)
		if err != nil {
			return err
		}
		return runRsyncSession(ctx, peer, source.Path, prefix, true)
	}
	return runRsyncSession(ctx, peer, destination.Path, rsyncPhysicalCD(source.Path), false)
}

// SSH channel close is cooperative. Give it time to clean up partial files
// before aborting the transfer's exclusive graph to unblock a stalled peer.
func watchRsyncCancel(ctx context.Context, graph *clientssh.Graph) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(stopped)
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			select {
			case <-done:
				return
			default:
			}
			graph.Abort()
		}
	})
	return func() {
		close(done)
		if !stop() {
			<-stopped
		}
	}
}

type rsyncDiscard struct{ io.Writer }

func (rsyncDiscard) Close() error { return nil }

func newRsyncClient(upload bool) (*rsyncclient.Client, error) {
	opts := []rsyncclient.Option{rsyncclient.WithStderr(rsyncDiscard{io.Discard})}
	if upload {
		opts = append(opts, rsyncclient.WithSender())
	}
	// Match cp's recursive permission-preserving copy, not rsync archive
	// mode. No links, devices, delete, inplace, or retained partial files.
	return rsyncclient.New([]string{"-rp", "--ignore-times"}, opts...)
}

func rsyncShellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

// Always run stock rsync on a fixed ./ operand, never a user-derived glob.
// Check the shell's physical path against the path preflighted over SFTP;
// the sentinel preserves directory names ending in a newline in $(...).
func rsyncPhysicalCD(dir string) string {
	return "cd -P " + rsyncShellQuote(dir) + " && " + rsyncVerifyPWD(dir)
}

func rsyncVerifyPWD(dir string) string {
	return "[ \"$(pwd -P && printf x)\" = " + rsyncShellQuote(dir+"\nx") + " ] && "
}

func rsyncRemoteDirectory(target sftp.Endpoint, missing bool) (string, error) {
	prefix := "command -v rsync >/dev/null 2>&1 || exit 127; "
	if !missing {
		return prefix + rsyncPhysicalCD(target.Path), nil
	}
	// Create only components found missing; mkdir without -p rejects a
	// conflicting file or symlink, rather than following or replacing it.
	var create []string
	for current := target.Path; ; current = target.FS.Dir(current) {
		info, err := target.FS.Lstat(current)
		if err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("rsync: destination component %q must be a directory", current)
			}
			prefix += rsyncPhysicalCD(current)
			break
		}
		if !errors.Is(err, os.ErrNotExist) || target.FS.Dir(current) == current {
			return "", fmt.Errorf("rsync: destination component %q: %w", current, err)
		}
		create = append(create, current)
	}
	for i := len(create) - 1; i >= 0; i-- {
		dir := create[i]
		component := rsyncShellQuote("./" + target.FS.Base(dir))
		prefix += "mkdir " + component + " && cd -P " + component + " && " + rsyncVerifyPWD(dir)
	}
	return prefix, nil
}

func checkRemoteRsync(ctx context.Context, peer *ssh.Client) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session, err := peer.NewSession()
	if err != nil {
		return fmt.Errorf("open ssh session for rsync preflight: %w", err)
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	if err := session.Run("command -v rsync >/dev/null 2>&1"); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("remote rsync is unavailable; install stock rsync on the SSH host or use --backend=sftp")
	}
	return nil
}

func runRsyncSession(ctx context.Context, peer *ssh.Client, local, remotePrefix string, upload bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, err := newRsyncClient(upload)
	if err != nil {
		return err
	}
	command := remotePrefix + "exec rsync"
	for _, arg := range client.ServerCommandOptions("./") {
		command += " " + rsyncShellQuote(arg)
	}
	session, err := peer.NewSession()
	if err != nil {
		return fmt.Errorf("open ssh session for rsync: %w", err)
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	out, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	in, err := session.StdinPipe()
	if err != nil {
		return err
	}
	session.Stderr = io.Discard
	if err := session.Start(command); err != nil {
		return fmt.Errorf("start remote command for rsync: %w", err)
	}
	runErr := runRsyncHelperProcess(ctx, upload, local, out, in)
	if runErr != nil {
		_ = session.Close()
	}
	waitErr := session.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if waitErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(waitErr, &exitErr) {
			if exitErr.ExitStatus() == 127 {
				return errors.New("remote rsync is unavailable; use --backend=sftp")
			}
			return fmt.Errorf("remote rsync failed (exit %d)", exitErr.ExitStatus())
		}
		if runErr == nil {
			return errors.New("remote rsync failed to report a successful exit")
		}
	}
	if runErr != nil {
		return fmt.Errorf("rsync transfer failed: %w", runErr)
	}
	return nil
}

type rsyncStream struct {
	io.Reader
	io.Writer
	io.Closer
}

// RsyncHelperCommand is the internal re-exec entry point for rsync protocol I/O.
// A child keeps protocol parsing out of the credential-bearing agent and lets
// the receiver apply its process-wide Landlock filesystem restriction.
const RsyncHelperCommand = "__warden-rsync"

type rsyncStdio struct{}

func (rsyncStdio) Close() error { return errors.Join(os.Stdin.Close(), os.Stdout.Close()) }

func RunRsyncHelper(role, path string) int {
	if role != "sender" && role != "receiver" {
		return 2
	}
	upload := role == "sender"
	client, err := newRsyncClient(upload)
	if err == nil {
		if upload {
			path += "/" // send the tree contents into the already-resolved target
		}
		_, err = client.Run(context.Background(), rsyncStream{Reader: os.Stdin, Writer: os.Stdout, Closer: rsyncStdio{}}, []string{path})
	}
	if err != nil {
		return 1
	}
	return 0
}

func runRsyncHelperProcess(ctx context.Context, upload bool, path string, remoteOut io.Reader, remoteIn io.WriteCloser) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	role := "receiver"
	if upload {
		role = "sender"
	}
	cmd := exec.Command(executable, RsyncHelperCommand, role, path)
	cmd.Env = []string{} // the protocol helper needs no environment or credentials
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()
	stop := context.AfterFunc(ctx, func() { _ = stdin.Close() })
	defer stop()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(stdin, remoteOut)
		_ = stdin.Close()
	}()
	_, copyErr := io.Copy(remoteIn, stdout)
	_ = remoteIn.Close()
	// An SSH write error must unblock the helper's output and let its
	// receiver see EOF so it can clean up its own incomplete temporary file.
	if copyErr != nil {
		_ = stdin.Close()
		_, _ = io.Copy(io.Discard, stdout)
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	return copyErr
}
