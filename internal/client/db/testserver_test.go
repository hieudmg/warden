package db

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// errAuthFailed is returned by test SSH server auth callbacks.
var errAuthFailed = errors.New("authentication failed")

// ---------------------------------------------------------------------------
// fakeMySQLServer: a minimal MySQL server stub. It speaks just enough of
// the wire protocol to complete a native-password handshake and answer
// each COM_QUERY with a canned result set, an OK packet, or an error.
// ---------------------------------------------------------------------------

type fakeMySQLServer struct {
	addr string
	ln   net.Listener

	mu      sync.Mutex
	seen    []string
	conns   int
	block   bool
	columns []string
	rows    [][]string
	errMsg  string
}

// newFakeMySQLServer starts a stub MySQL server. Queries whose first token
// looks like a read return a result set built from columns/rows; everything
// else returns an OK packet.
func newFakeMySQLServer(t *testing.T, columns []string, rows [][]string) *fakeMySQLServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mysql listen: %v", err)
	}
	s := &fakeMySQLServer{addr: ln.Addr().String(), ln: ln, columns: columns, rows: rows}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeMySQLServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *fakeMySQLServer) connectionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *fakeMySQLServer) queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

// setBlock makes the server accept connections but never answer queries,
// simulating a hung database for cancellation tests.
func (s *fakeMySQLServer) setBlock(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.block = v
}

func (s *fakeMySQLServer) handle(conn net.Conn) {
	defer conn.Close()

	if err := writePacket(conn, 0, s.greeting()); err != nil {
		return
	}
	// Client handshake response (auth + db name); contents ignored.
	if _, err := readPacket(conn); err != nil {
		return
	}
	if err := writePacket(conn, 2, okPacket()); err != nil {
		return
	}

	for {
		pkt, err := readPacket(conn)
		if err != nil {
			return
		}
		switch pkt[0] {
		case 0x03: // COM_QUERY
			s.mu.Lock()
			query := string(pkt[1:])
			s.seen = append(s.seen, query)
			block := s.block
			s.mu.Unlock()
			if block {
				io.Copy(io.Discard, conn) // wait for the driver to close us
				return
			}
			s.respond(conn, query)
		case 0x01: // COM_QUIT
			return
		case 0x0e: // COM_PING
			if err := writePacket(conn, 1, okPacket()); err != nil {
				return
			}
		}
	}
}

func (s *fakeMySQLServer) respond(conn net.Conn, query string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := 1
	if s.errMsg != "" {
		writePacket(conn, byte(seq), s.errPacket(s.errMsg))
		return
	}
	upper := strings.ToUpper(strings.TrimSpace(query))
	if isReadStatement(upper) {
		writePacket(conn, byte(seq), lenencBytes(uint64(len(s.columns))))
		seq++
		for _, c := range s.columns {
			writePacket(conn, byte(seq), columnDef(c))
			seq++
		}
		writePacket(conn, byte(seq), eofPacket())
		seq++
		for _, row := range s.rows {
			writePacket(conn, byte(seq), rowPacket(row))
			seq++
		}
		writePacket(conn, byte(seq), eofPacket())
		return
	}
	writePacket(conn, byte(seq), okPacket())
}

func isReadStatement(upper string) bool {
	for _, prefix := range []string{"SELECT", "SHOW", "DESCRIBE", "EXPLAIN", "PRAGMA", "WITH"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// greeting builds a Protocol::HandshakeV10 packet advertising protocol 41,
// secure connection, plugin auth, and mysql_native_password.
func (s *fakeMySQLServer) greeting() []byte {
	scramble := []byte("0123456789abcdefghijklm") // 21 bytes
	var b bytes.Buffer
	b.WriteByte(10)
	b.WriteString("8.0.36-warden-fake\x00")
	binary.Write(&b, binary.LittleEndian, uint32(1234))          // thread id
	b.Write(scramble[:8])                                        // auth plugin data part 1
	b.WriteByte(0)                                               // filler
	binary.Write(&b, binary.LittleEndian, uint16(0x0200|0x8000)) // PROTOCOL_41 | SECURE_CONNECTION
	b.WriteByte(0x21)                                            // utf8_general_ci
	binary.Write(&b, binary.LittleEndian, uint16(0x0002))        // SERVER_STATUS_AUTOCOMMIT
	binary.Write(&b, binary.LittleEndian, uint16(0x0008))        // PLUGIN_AUTH (upper flags)
	b.WriteByte(21)                                              // auth plugin data length
	b.Write(make([]byte, 10))                                    // reserved
	b.Write(scramble[8:21])                                      // auth plugin data part 2 (13 bytes)
	b.WriteByte(0)
	b.WriteString("mysql_native_password\x00")
	return b.Bytes()
}

func okPacket() []byte {
	// 0x00 header, 0 affected rows, 0 last insert id, AUTOCOMMIT status,
	// 0 warnings.
	return []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
}

func eofPacket() []byte {
	// 0xfe header, 0 warnings, AUTOCOMMIT status.
	return []byte{0xfe, 0x00, 0x00, 0x02, 0x00}
}

func (s *fakeMySQLServer) errPacket(msg string) []byte {
	var b bytes.Buffer
	b.WriteByte(0xff)
	binary.Write(&b, binary.LittleEndian, uint16(1146)) // ER_NO_SUCH_TABLE
	b.WriteByte('#')
	b.WriteString("42S02")
	b.WriteString(msg)
	return b.Bytes()
}

// columnDef builds a Protocol::ColumnDefinition41 packet.
func columnDef(name string) []byte {
	var b bytes.Buffer
	writeLenencString(&b, "def")
	writeLenencString(&b, "")
	writeLenencString(&b, "")
	writeLenencString(&b, "")
	writeLenencString(&b, name)
	writeLenencString(&b, "")
	b.WriteByte(0x0c) // length of fixed-length fields
	binary.Write(&b, binary.LittleEndian, uint16(0x21))
	binary.Write(&b, binary.LittleEndian, uint32(255))
	b.WriteByte(0xfd) // VAR_STRING
	binary.Write(&b, binary.LittleEndian, uint16(0))
	b.WriteByte(0)
	b.Write([]byte{0, 0})
	return b.Bytes()
}

func rowPacket(vals []string) []byte {
	var b bytes.Buffer
	for _, v := range vals {
		writeLenencString(&b, v)
	}
	return b.Bytes()
}

func lenencBytes(v uint64) []byte {
	switch {
	case v < 251:
		return []byte{byte(v)}
	case v < 1<<16:
		return []byte{0xfc, byte(v), byte(v >> 8)}
	case v < 1<<24:
		return []byte{0xfd, byte(v), byte(v >> 8), byte(v >> 16)}
	default:
		return []byte{0xfe, byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
			byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56)}
	}
}

func writeLenencString(b *bytes.Buffer, s string) {
	b.Write(lenencBytes(uint64(len(s))))
	b.WriteString(s)
}

func writePacket(conn net.Conn, seq byte, payload []byte) error {
	header := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func readPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	n := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// ---------------------------------------------------------------------------
// Minimal SSH test server: password auth plus direct-tcpip forwarding so
// jump chains and DB tunnels can be exercised in-process.
// ---------------------------------------------------------------------------

type tunnelSSHServer struct {
	addr    string
	hostKey ssh.PublicKey
	ln      net.Listener

	mu   sync.Mutex
	open int
}

func newTunnelSSHServer(t *testing.T, password string) *tunnelSSHServer {
	t.Helper()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare(pass, []byte(password)) == 1 {
				return nil, nil
			}
			return nil, errAuthFailed
		},
	}
	hostSigner := newTestSigner(t)
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ssh listen: %v", err)
	}
	srv := &tunnelSSHServer{
		addr:    ln.Addr().String(),
		hostKey: hostSigner.PublicKey(),
		ln:      ln,
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConn(conn, cfg)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return srv
}

func (s *tunnelSSHServer) handleConn(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	s.mu.Lock()
	s.open++
	s.mu.Unlock()
	defer func() {
		sconn.Close()
		s.mu.Lock()
		s.open--
		s.mu.Unlock()
	}()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "direct-tcpip":
			go forwardDirectTCPIP(newCh)
		default:
			newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

func (s *tunnelSSHServer) openConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open
}

// waitClosed polls until no SSH connections remain, failing after timeout.
func (s *tunnelSSHServer) waitClosed(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.openConns() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ssh server still has %d open connections", s.openConns())
}

// forwardDirectTCPIP forwards a direct-tcpip channel to the requested host,
// enabling ssh.Client.Dial through a jump server.
func forwardDirectTCPIP(newCh ssh.NewChannel) {
	var dest struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &dest); err != nil {
		newCh.Reject(ssh.ConnectionFailed, "malformed direct-tcpip request")
		return
	}
	upstream, err := net.Dial("tcp", net.JoinHostPort(dest.Host, strconv.FormatUint(uint64(dest.Port), 10)))
	if err != nil {
		newCh.Reject(ssh.ConnectionFailed, "dial failed")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		upstream.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		defer ch.Close()
		defer upstream.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(ch, upstream) }()
		go func() { defer wg.Done(); io.Copy(upstream, ch) }()
		wg.Wait()
	}()
}

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("make signer: %v", err)
	}
	return signer
}

// newEchoServer accepts TCP connections and echoes everything it receives.
func newEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}
