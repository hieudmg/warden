package crypto

import (
	"context"
	"errors"
	"sync"
)

var ErrVaultLocked = errors.New("vault_locked")

// Vault is the only long-lived runtime key owner. Leases span the operation AND
// response delivery. Lock cancels leases, rejects acquisition/key delivery, and
// waits for every lease before acknowledging. Clearing Go memory is best effort.
type Vault struct {
	mu         sync.Mutex
	cond       *sync.Cond
	key        *[32]byte
	generation uint64
	locking    bool
	active     map[*leaseContext]context.CancelFunc
}

func NewVault() *Vault {
	v := &Vault{active: make(map[*leaseContext]context.CancelFunc)}
	v.cond = sync.NewCond(&v.mu)
	return v
}
func (v *Vault) Generation() uint64 { v.mu.Lock(); defer v.mu.Unlock(); return v.generation }
func (v *Vault) Unlocked() bool     { v.mu.Lock(); defer v.mu.Unlock(); return v.key != nil && !v.locking }
func (v *Vault) Unlock(key []byte, generation uint64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(key) != 32 || v.locking || generation != v.generation {
		return ErrVaultLocked
	}
	if v.key != nil {
		clear(v.key[:])
	}
	v.key = new([32]byte)
	copy(v.key[:], key)
	return nil
}
func (v *Vault) Acquire(parent context.Context) (context.Context, func(), error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil || v.locking {
		return nil, nil, ErrVaultLocked
	}
	ctx, cancel := context.WithCancel(parent)
	// A non-zero-sized holder gives each active lease a distinct identity.
	holder := &leaseContext{ctx: ctx}
	v.active[holder] = cancel
	var once sync.Once
	return ctx, func() {
		once.Do(func() { v.mu.Lock(); delete(v.active, holder); cancel(); v.cond.Broadcast(); v.mu.Unlock() })
	}, nil
}

type leaseContext struct{ ctx context.Context }

// KeyForLease returns a transient same-DEK copy only to its exact live lease.
// Fresh authorization belongs to the caller; retain the lease through delivery.
func (v *Vault) KeyForLease(ctx context.Context) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil || v.locking || ctx.Err() != nil {
		return nil, ErrVaultLocked
	}
	for lease := range v.active {
		if lease.ctx == ctx {
			return append([]byte(nil), v.key[:]...), nil
		}
	}
	return nil, ErrVaultLocked
}

func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for v.locking {
		v.cond.Wait()
	}
	v.locking = true
	v.generation++
	for _, cancel := range v.active {
		cancel()
	}
	for len(v.active) > 0 {
		v.cond.Wait()
	}
	if v.key != nil {
		clear(v.key[:])
		v.key = nil
	}
	v.locking = false
	v.cond.Broadcast()
}
func (v *Vault) transform(input, aad []byte, encrypt bool) ([]byte, error) {
	_, release, err := v.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer release()
	v.mu.Lock()
	var c Codec
	copy(c.Key[:], v.key[:])
	v.mu.Unlock()
	defer clear(c.Key[:])
	if encrypt {
		return c.Encrypt(input, aad)
	}
	return c.Decrypt(input, aad)
}
func (v *Vault) Encrypt(p, aad []byte) ([]byte, error) { return v.transform(p, aad, true) }
func (v *Vault) Decrypt(p, aad []byte) ([]byte, error) { return v.transform(p, aad, false) }
