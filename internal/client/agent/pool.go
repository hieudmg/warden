package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"

	clientssh "warden/internal/client/ssh"
	"warden/internal/model"

	golangssh "golang.org/x/crypto/ssh"
)

// GraphDialer establishes a reusable SSH graph for one resolved bundle. The
// dialer is called without the pool mutex held, so a slow SSH handshake does
// not block operations using other cached graphs.
type GraphDialer func(context.Context, model.SSHBundle) (*clientssh.Graph, error)

// DefaultGraphDialer preserves the normal SSH host-key and jump-chain
// behavior for the agent's production pool.
func DefaultGraphDialer(ctx context.Context, bundle model.SSHBundle) (*clientssh.Graph, error) {
	return clientssh.DialGraph(ctx, bundle, clientssh.DialOptions{})
}

// NewDefaultPool creates the production graph pool using ssh.DialGraph.
func NewDefaultPool(now func() time.Time, ttl time.Duration) *Pool {
	return NewPool(DefaultGraphDialer, now, ttl)
}

var (
	// ErrPoolClosed reports an acquisition attempted after the agent pool has
	// been shut down.
	ErrPoolClosed = errors.New("agent pool is closed")
	// ErrGraphRetired reports a graph that was retired while it was being
	// acquired. A later acquisition may establish a replacement.
	ErrGraphRetired = errors.New("agent graph was retired")
)

type entry struct {
	graph    *clientssh.Graph
	active   int
	lastUsed time.Time
	retired  bool
	ready    chan struct{}
	dialErr  error
	dialing  bool
	closed   bool
}

// Pool caches SSH graphs by the complete resolved bundle. A graph remains
// alive while at least one lease owns it, and is closed only after it has been
// idle for the configured TTL or has been retired.
type Pool struct {
	mu sync.Mutex

	dial GraphDialer
	now  func() time.Time
	ttl  time.Duration

	entries       map[[sha256.Size]byte]*entry
	emptyCh       chan struct{}
	retiredActive int
	used          bool
	closed        bool
}

// NewPool creates a graph pool. The clock and TTL are injectable so expiry can
// be tested without sleeping. A nil clock uses time.Now; a non-positive TTL
// means that an idle graph is eligible for the next Expire call.
func NewPool(dial GraphDialer, now func() time.Time, ttl time.Duration) *Pool {
	if now == nil {
		now = time.Now
	}
	return &Pool{
		dial:    dial,
		now:     now,
		ttl:     ttl,
		entries: make(map[[sha256.Size]byte]*entry),
		emptyCh: make(chan struct{}, 1),
	}
}

// Acquire obtains a lease for bundle. Concurrent acquisitions for a bundle
// share one in-progress dial; followers either receive the resulting graph or
// the same dial error without starting a second handshake.
func (p *Pool) Acquire(ctx context.Context, bundle model.SSHBundle) (*Lease, error) {
	if ctx == nil {
		return nil, errors.New("agent pool acquire context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrPoolClosed
	}

	key, err := bundleFingerprint(bundle)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.ensureLocked()
	for {
		if p.closed {
			p.mu.Unlock()
			return nil, ErrPoolClosed
		}

		e, ok := p.entries[key]
		if !ok {
			e = &entry{
				active:   1, // reserve the lease before dialing
				lastUsed: p.now(),
				ready:    make(chan struct{}),
				dialing:  true,
			}
			p.entries[key] = e
			dial := p.dial
			p.mu.Unlock()

			var graph *clientssh.Graph
			if dial == nil {
				err = errors.New("agent graph dialer is nil")
			} else {
				graph, err = dial(ctx, bundle)
			}
			if err == nil && graph == nil {
				err = errors.New("agent graph dialer returned nil graph")
			}

			p.mu.Lock()
			// Retire, Close, or a replacement cannot reuse this entry. In
			// those cases the newly dialed graph is still owned by this
			// acquisition attempt and must be closed outside the lock.
			keep := err == nil && !p.closed && !e.retired && p.entries[key] == e
			if keep {
				e.graph = graph
				e.dialing = false
				e.dialErr = nil
				p.used = true
				close(e.ready)
				p.mu.Unlock()
				return &Lease{pool: p, entry: e}, nil
			}

			if err == nil {
				switch {
				case p.closed:
					err = ErrPoolClosed
				case e.retired:
					err = ErrGraphRetired
				default:
					err = ErrGraphRetired
				}
			}
			e.graph = nil
			if e.retired && e.active > 0 {
				p.retiredActive--
			}
			e.active = 0
			e.dialing = false
			e.dialErr = err
			e.closed = true
			if p.entries[key] == e {
				delete(p.entries, key)
				p.signalEmptyLocked()
			}
			close(e.ready)
			p.mu.Unlock()
			closeGraph(graph)
			return nil, err
		}

		if e.dialing {
			ready := e.ready
			p.mu.Unlock()
			select {
			case <-ready:
				p.mu.Lock()
				if e.dialErr != nil {
					err := e.dialErr
					p.mu.Unlock()
					return nil, err
				}
				if e.graph == nil || e.retired || p.closed || p.entries[key] != e {
					p.mu.Unlock()
					return nil, ErrGraphRetired
				}
				e.active++
				p.mu.Unlock()
				return &Lease{pool: p, entry: e}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		if e.graph != nil && !e.retired {
			e.active++
			p.mu.Unlock()
			return &Lease{pool: p, entry: e}, nil
		}
		// Retired entries are normally removed immediately. Keep this
		// branch defensive for callers racing an explicit Retire.
		if p.entries[key] == e {
			delete(p.entries, key)
			p.signalEmptyLocked()
		}
	}
}

// Lease owns one active reference to a pooled graph. Release is idempotent;
// the graph remains available to other leases until the final release and its
// idle TTL have elapsed.
type Lease struct {
	pool  *Pool
	entry *entry
	once  sync.Once
}

// Target returns the borrowed target SSH client. The lease must remain held
// until all operation-specific sessions and tunnels using the target close.
func (l *Lease) Target() *golangssh.Client {
	if l == nil || l.entry == nil || l.entry.graph == nil {
		return nil
	}
	return l.entry.graph.Target()
}

// Graph returns the graph owned by this lease. Callers must not close it;
// Release transfers lifetime management back to the pool.
func (l *Lease) Graph() *clientssh.Graph {
	if l == nil || l.entry == nil {
		return nil
	}
	return l.entry.graph
}

// Release gives the lease back to its pool. It never closes a graph while an
// operation still holds another lease, and may be called more than once.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.pool != nil {
			l.pool.release(l.entry)
		}
	})
}

// Retire removes this lease's graph from future lookups. Existing leases are
// allowed to finish; the graph closes after their final Release. Retiring does
// not replay or otherwise restart the current operation.
func (l *Lease) Retire() {
	if l == nil || l.pool == nil {
		return
	}
	l.pool.retireEntry(l.entry)
}

func (p *Pool) release(e *entry) {
	if p == nil || e == nil {
		return
	}
	var graph *clientssh.Graph
	p.mu.Lock()
	if e.active > 0 {
		e.active--
	}
	if e.active == 0 {
		e.lastUsed = p.now()
		if e.retired {
			if p.retiredActive > 0 {
				p.retiredActive--
			}
		}
		if e.retired && !e.closed {
			e.closed = true
			graph = e.graph
			e.graph = nil
		}
	}
	p.signalEmptyLocked()
	p.mu.Unlock()
	closeGraph(graph)
}

// Retire removes a graph from future acquisitions. The value may be either a
// model.SSHBundle or a *Lease; accepting both forms keeps retirement tied to
// the failure site without making callers reconstruct a bundle. It is safe to
// call when no matching graph exists.
func (p *Pool) Retire(value any) {
	if p == nil {
		return
	}
	if lease, ok := value.(*Lease); ok {
		if lease != nil {
			lease.Retire()
		}
		return
	}
	bundle, ok := value.(model.SSHBundle)
	if !ok {
		return
	}
	key, err := bundleFingerprint(bundle)
	if err != nil {
		return
	}
	p.mu.Lock()
	e := p.entries[key]
	p.retireLocked(key, e)
	p.mu.Unlock()
	p.closeRetired(e)
}

// RetireBundle is an explicit alias for Retire for callers that prefer a
// name distinguishing the bundle key from a lease.
func (p *Pool) RetireBundle(bundle model.SSHBundle) { p.Retire(bundle) }

// RetireLease is an explicit lease-oriented retirement helper.
func (p *Pool) RetireLease(lease *Lease) { p.Retire(lease) }

func (p *Pool) retireEntry(e *entry) {
	if p == nil || e == nil {
		return
	}
	p.mu.Lock()
	var key [sha256.Size]byte
	for candidate, current := range p.entries {
		if current == e {
			key = candidate
			break
		}
	}
	p.retireLocked(key, e)
	p.mu.Unlock()
	p.closeRetired(e)
}

func (p *Pool) retireLocked(key [sha256.Size]byte, e *entry) {
	if e == nil {
		return
	}
	if !e.retired {
		e.retired = true
		if e.active > 0 {
			p.retiredActive++
		}
	}
	if p.entries[key] == e {
		delete(p.entries, key)
		p.signalEmptyLocked()
	}
}

func (p *Pool) closeRetired(e *entry) {
	if e == nil {
		return
	}
	var graph *clientssh.Graph
	p.mu.Lock()
	if e.active == 0 && !e.dialing && !e.closed {
		e.closed = true
		graph = e.graph
		e.graph = nil
	}
	p.mu.Unlock()
	closeGraph(graph)
}

// Expire removes and closes every graph that has been idle for at least the
// configured TTL. Active and in-progress entries are never expired.
func (p *Pool) Expire() {
	if p == nil {
		return
	}
	var graphs []*clientssh.Graph
	p.mu.Lock()
	p.ensureLocked()
	now := p.now()
	for key, e := range p.entries {
		if e.dialing || e.retired || e.active != 0 || now.Sub(e.lastUsed) < p.ttl {
			continue
		}
		delete(p.entries, key)
		e.retired = true
		if !e.closed {
			e.closed = true
			graphs = append(graphs, e.graph)
			e.graph = nil
		}
	}
	if p.isEmptyLocked() {
		p.signalEmptyLocked()
	}
	p.mu.Unlock()
	for _, graph := range graphs {
		closeGraph(graph)
	}
}

// Empty reports whether the pool has no cached or in-progress entries.
func (p *Pool) Empty() bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isEmptyLocked()
}

// TTL returns the configured idle expiry duration.
func (p *Pool) TTL() time.Duration {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ttl
}

// EmptySignal returns a notification channel that receives a signal whenever
// the pool becomes empty. The channel remains usable across later
// acquisitions, and is intended for the agent server's shutdown watcher.
func (p *Pool) EmptySignal() <-chan struct{} {
	if p == nil {
		ch := make(chan struct{}, 1)
		ch <- struct{}{}
		return ch
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ensureLocked()
	return p.emptyCh
}

// Used reports whether at least one graph acquisition has completed. A server
// uses this to distinguish a freshly started empty pool from an idle pool that
// should terminate.
func (p *Pool) Used() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.used
}

// Close retires all cached graphs. Active leases continue to own their graph
// until Release; idle graphs are closed before Close returns.
func (p *Pool) Close() error {
	if p == nil {
		return nil
	}
	var graphs []*clientssh.Graph
	p.mu.Lock()
	p.ensureLocked()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	for key, e := range p.entries {
		delete(p.entries, key)
		if !e.retired {
			e.retired = true
			if e.active > 0 {
				p.retiredActive++
			}
		}
		if e.active == 0 && !e.dialing && !e.closed {
			e.closed = true
			graphs = append(graphs, e.graph)
			e.graph = nil
		}
	}
	p.signalEmptyLocked()
	p.mu.Unlock()
	for _, graph := range graphs {
		closeGraph(graph)
	}
	return nil
}

func (p *Pool) ensureLocked() {
	if p.entries == nil {
		p.entries = make(map[[sha256.Size]byte]*entry)
	}
	if p.emptyCh == nil {
		p.emptyCh = make(chan struct{}, 1)
	}
	if p.now == nil {
		p.now = time.Now
	}
}

func (p *Pool) signalEmptyLocked() {
	p.ensureLocked()
	if !p.isEmptyLocked() {
		return
	}
	select {
	case p.emptyCh <- struct{}{}:
	default:
		// A watcher already has an empty notification waiting.
	}
}

func (p *Pool) isEmptyLocked() bool {
	return len(p.entries) == 0 && p.retiredActive == 0
}

func bundleFingerprint(bundle model.SSHBundle) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// FingerprintBundle returns the SHA-256 identity used by Pool for a complete
// bundle, including its credentials and every jump/proxy field.
func FingerprintBundle(bundle model.SSHBundle) [sha256.Size]byte {
	key, _ := bundleFingerprint(bundle)
	return key
}

// BundleFingerprint is a descriptive alias for FingerprintBundle.
func BundleFingerprint(bundle model.SSHBundle) [sha256.Size]byte {
	return FingerprintBundle(bundle)
}

func closeGraph(graph *clientssh.Graph) {
	if graph != nil {
		_ = graph.Close()
	}
}
