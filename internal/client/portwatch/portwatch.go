// Package portwatch watches remote TCP listeners and exposes matching ports
// through loopback-only local SSH forwards.
package portwatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	golangssh "golang.org/x/crypto/ssh"

	clientssh "warden/internal/client/ssh"
	"warden/internal/client/terminal"
	"warden/internal/model"
)

const (
	remoteListenerCommand        = "ss -H -ltn"
	remoteListenerProcessCommand = "ss -H -ltnp"
	pollInterval                 = 2 * time.Second
)

type portRange struct {
	first int
	last  int
}

// PortRanges is a validated set of TCP port ranges.
type PortRanges struct {
	ranges []portRange
}

// ParsePortRanges parses a comma-separated list of TCP ports and inclusive
// ranges, for example "3000,5000-6000".
func ParsePortRanges(spec string) (PortRanges, error) {
	if spec == "" {
		return PortRanges{}, errors.New("port range list must not be empty")
	}
	var result PortRanges
	for _, part := range strings.Split(spec, ",") {
		if part == "" || strings.TrimSpace(part) != part {
			return PortRanges{}, fmt.Errorf("invalid port range %q", part)
		}
		low, high, hasDash := strings.Cut(part, "-")
		if hasDash && (low == "" || high == "" || strings.Contains(high, "-")) {
			return PortRanges{}, fmt.Errorf("invalid port range %q", part)
		}
		first, err := parsePort(low)
		if err != nil {
			return PortRanges{}, fmt.Errorf("invalid port range %q: %w", part, err)
		}
		last := first
		if hasDash {
			last, err = parsePort(high)
			if err != nil {
				return PortRanges{}, fmt.Errorf("invalid port range %q: %w", part, err)
			}
		}
		if first > last {
			return PortRanges{}, fmt.Errorf("invalid port range %q: start must not exceed end", part)
		}
		result.ranges = append(result.ranges, portRange{first: first, last: last})
	}
	return result, nil
}

func parsePort(raw string) (int, error) {
	if raw == "" {
		return 0, errors.New("port must not be empty")
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("port %q must contain only digits", raw)
		}
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %q must be between 1 and 65535", raw)
	}
	return port, nil
}

// Contains reports whether port is in one of the parsed ranges.
func (r PortRanges) Contains(port int) bool {
	for _, candidate := range r.ranges {
		if port >= candidate.first && port <= candidate.last {
			return true
		}
	}
	return false
}

// Watch connects to the saved SSH bundle and watches its TCP listeners until
// ctx is canceled. Matching ports are forwarded to the same port on localhost.
func Watch(ctx context.Context, bundle model.SSHBundle, rangeSpec string, stdout, stderr io.Writer) error {
	var openTerminal func() (terminal.Session, error)
	if terminalOutput(stdout) {
		openTerminal = terminal.NewSession
	}
	return watchBundle(ctx, bundle, rangeSpec, stdout, stderr, openTerminal, pollInterval)
}

func watchBundle(ctx context.Context, bundle model.SSHBundle, rangeSpec string, stdout, stderr io.Writer, openTerminal func() (terminal.Session, error), interval time.Duration) error {
	ranges, err := ParsePortRanges(rangeSpec)
	if err != nil {
		return err
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	graph, err := clientssh.DialGraph(ctx, bundle, clientssh.DialOptions{})
	if err != nil {
		return err
	}
	defer graph.Close()
	defer graph.Abort() // Close the outer transport before closing the jump chain.

	target := graph.Target()
	scan := func(ctx context.Context) (map[int]string, error) {
		return scanListeningPorts(ctx, func(ctx context.Context, command string) (string, error) {
			return runListenerCommand(ctx, target, command)
		})
	}
	if openTerminal != nil {
		session, err := openTerminal()
		if err == nil {
			if session.SupportsANSI() {
				return runFullScreen(ctx, session, stdout, bundle.Target.Name, rangeSpec, func(ctx context.Context, update func([]portRow)) error {
					// Watch owns this graph exclusively. On quit, close its outer
					// socket to interrupt SSH startup and channel I/O, even across jumps.
					stopAbort := context.AfterFunc(ctx, graph.Abort)
					defer stopAbort()
					return watchPortsWithView(ctx, scan, ranges, target, io.Discard, io.Discard, interval, update, &processProbe{bundle: bundle})
				})
			}
			_ = session.Restore()
		}
	}
	fmt.Fprintf(stdout, "port-watch: watching %s on %s; forwards listen on 127.0.0.1\n", rangeSpec, bundle.Target.Name)
	return watchPorts(ctx, scan, ranges, target, stdout, stderr, interval)
}

// watchPorts owns the changing set of local listeners. The scan callback is
// called immediately and then at interval until cancellation.
func watchPorts(ctx context.Context, scan func(context.Context) (map[int]string, error), ranges PortRanges, target portDialer, stdout, stderr io.Writer, interval time.Duration) error {
	return watchPortsWithView(ctx, scan, ranges, target, stdout, stderr, interval, nil, nil)
}

func watchPortsWithView(ctx context.Context, scan func(context.Context) (map[int]string, error), ranges PortRanges, target portDialer, stdout, stderr io.Writer, interval time.Duration, update func([]portRow), probe *processProbe) error {
	active := make(map[int]*portForward)
	lastFailure := make(map[int]error)
	var history map[int]portRow
	if update != nil {
		history = make(map[int]portRow)
	}
	publish := func() {
		rows := make([]portRow, 0, len(history))
		for _, port := range slices.Sorted(maps.Keys(history)) {
			rows = append(rows, history[port])
		}
		update(rows)
	}
	defer func() {
		for _, forward := range active {
			_ = forward.Close()
		}
	}()

	for {
		listening, err := scan(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("inspect remote TCP listeners: %w", err)
		}
		for port := range listening {
			if !ranges.Contains(port) {
				delete(listening, port)
			}
		}

		for port := range lastFailure {
			if _, ok := listening[port]; !ok {
				delete(lastFailure, port)
			}
		}
		for port, forward := range active {
			if _, ok := listening[port]; ok {
				continue
			}
			_ = forward.Close()
			delete(active, port)
			fmt.Fprintf(stdout, "closed http://127.0.0.1:%d/ (remote listener stopped)\n", port)
		}
		for _, port := range slices.Sorted(maps.Keys(listening)) {
			if active[port] != nil {
				continue
			}
			forward, err := newPortForward(target, port)
			if err != nil {
				if prior := lastFailure[port]; prior == nil || prior.Error() != err.Error() {
					fmt.Fprintf(stderr, "port-watch: cannot forward localhost:%d: %v\n", port, err)
				}
				lastFailure[port] = err
				continue
			}
			active[port] = forward
			delete(lastFailure, port)
			fmt.Fprintf(stdout, "forwarding http://127.0.0.1:%d/ -> 127.0.0.1:%d\n", port, port)
		}

		var processNames <-chan map[int]string
		setProcessNames := func(names map[int]string) {
			changed := false
			for port := range listening {
				row := history[port]
				if row.process != names[port] {
					row.process = names[port]
					history[port] = row
					changed = true
				}
			}
			if changed {
				publish()
			}
		}
		if update != nil {
			for port, row := range history {
				if _, ok := listening[port]; !ok && !row.closed {
					history[port] = portRow{port: port, process: row.process, closed: true}
				}
			}
			for port, process := range listening {
				prior := history[port]
				if probe != nil && !prior.closed {
					// Avoid blanking a live name while its refresh is pending.
					process = prior.process
				}
				row := portRow{port: port, process: process}
				if err := lastFailure[port]; err != nil {
					row.failure = err.Error()
					row.conflict = isAddressInUse(err)
				}
				history[port] = row
			}
			publish()

			if probe != nil && len(listening) > 0 {
				processNames = probe.start(ctx)
				if processNames == nil {
					setProcessNames(nil)
				}
			}
		}

		// Only the authoritative scan controls the cadence. Accept optional
		// names during this interval, but never carry a result into a newer scan.
		timer := time.NewTimer(interval)
	waitForPoll:
		for {
			select {
			case names := <-processNames:
				probe.pending = nil
				processNames = nil
				setProcessNames(names)
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
				break waitForPoll
			}
		}
	}
}

func isAddressInUse(err error) bool {
	// Winsock returns WSAEADDRINUSE (10048), not the POSIX errno.
	return errors.Is(err, syscall.EADDRINUSE) || (runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(10048)))
}

func scanListeningPorts(ctx context.Context, run func(context.Context, string) (string, error)) (map[int]string, error) {
	output, err := run(ctx, remoteListenerCommand)
	if err != nil {
		return nil, err
	}
	return parseListeningPorts(output, false)
}

func runListenerCommand(ctx context.Context, client *golangssh.Client, command string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var stdout, stderr strings.Builder
	session.Stdout = &stdout
	session.Stderr = &stderr
	if err := session.Start(command); err != nil {
		return "", err
	}
	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	select {
	case <-ctx.Done():
		_ = session.Close()
		return "", ctx.Err()
	case err := <-wait:
		if err != nil {
			if stderr.Len() > 0 {
				return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
			}
			return "", err
		}
	}
	return stdout.String(), nil
}

var ssProcessTuple = regexp.MustCompile(`\("([^"]*)",pid=[0-9]+,fd=[0-9]+\)`)

func parseListeningPorts(output string, processes bool) (map[int]string, error) {
	listeners := make(map[int]string)
	for lineNumber, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "LISTEN" {
			continue
		}
		if len(fields) < 4 {
			return nil, fmt.Errorf("malformed ss listener row %d", lineNumber+1)
		}
		address := fields[3]
		separator := strings.LastIndexByte(address, ':')
		if separator < 0 || separator == len(address)-1 {
			return nil, fmt.Errorf("malformed local address %q in ss row %d", address, lineNumber+1)
		}
		port, err := strconv.Atoi(address[separator+1:])
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid TCP port in ss row %d: %q", lineNumber+1, address)
		}
		name := listeners[port]
		if processes && len(fields) > 5 && strings.HasPrefix(fields[5], "users:((") {
			for _, match := range ssProcessTuple.FindAllStringSubmatch(line, -1) {
				candidate := strings.TrimSpace(strings.Map(func(r rune) rune {
					if !unicode.IsPrint(r) {
						return -1
					}
					return r
				}, match[1]))
				// Choose one stable name across processes and addresses for this port.
				if candidate != "" && (name == "" || candidate < name) {
					name = candidate
				}
			}
		}
		listeners[port] = name
	}
	return listeners, nil
}

type portDialer interface {
	Dial(network, address string) (net.Conn, error)
}

type portForward struct {
	listener net.Listener
	target   portDialer
	done     chan struct{}
	mu       sync.Mutex
	closed   bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	once     sync.Once
}

func newPortForward(target portDialer, port int) (*portForward, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	forward := &portForward{
		listener: listener,
		target:   target,
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	go forward.accept()
	return forward, nil
}

func (f *portForward) accept() {
	for {
		local, err := f.listener.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			_ = local.Close()
			return
		}
		f.conns[local] = struct{}{}
		f.wg.Add(1)
		f.mu.Unlock()
		go f.serve(local)
	}
}

func (f *portForward) track(conn net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conns[conn] = struct{}{}
	return true
}

func (f *portForward) untrack(conn net.Conn) {
	f.mu.Lock()
	delete(f.conns, conn)
	f.mu.Unlock()
}

func (f *portForward) serve(local net.Conn) {
	defer f.wg.Done()
	defer f.untrack(local)
	defer local.Close()
	remote, err := f.dialRemote()
	if err != nil {
		return
	}
	if !f.track(remote) {
		_ = remote.Close()
		return
	}
	defer f.untrack(remote)
	defer remote.Close()
	go func() {
		_, _ = io.Copy(remote, local)
		_ = remote.Close()
	}()
	_, _ = io.Copy(local, remote)
}

func (f *portForward) dialRemote() (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.listener.Addr().(*net.TCPAddr).Port))
	resultCh := make(chan result)
	go func() {
		conn, err := f.target.Dial("tcp", address)
		select {
		case resultCh <- result{conn: conn, err: err}:
		case <-f.done:
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-f.done:
		return nil, net.ErrClosed
	}
}

func (f *portForward) Close() error {
	var err error
	f.once.Do(func() {
		close(f.done)
		f.mu.Lock()
		f.closed = true
		connections := make([]net.Conn, 0, len(f.conns))
		for conn := range f.conns {
			connections = append(connections, conn)
		}
		f.mu.Unlock()
		if closeErr := f.listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = closeErr
		}
		for _, conn := range connections {
			_ = conn.Close()
		}
		f.wg.Wait()
	})
	return err
}
