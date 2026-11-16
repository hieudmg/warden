package profiles

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"warden/internal/crypto"
	"warden/internal/model"
	"warden/internal/store"
)

// The fake supplies real AEAD ciphertext and calls the ordinary Codec.Decrypt
// through a counted callback, not merely a counter on returned bundles.
type countedResolution struct {
	ssh                                map[int64]model.SSHProfile
	db                                 map[int64]model.DBProfile
	pairs                              map[int64]model.KeyPair
	codec                              crypto.Codec
	metadata, keyMetadata, secretLoads int
	decrypts                           []string
	stopAfter                          int
	afterMetadata                      func(int)
	afterSecretLoad                    func(int)
	afterDecrypt                       func(string)
	secretLoadAttempts                 []string
	closed                             bool
	closeCalls                         int
}

var errLookupStop = errors.New("test stopping condition: lookup bound exceeded")

func newCountedResolution() *countedResolution {
	return &countedResolution{ssh: map[int64]model.SSHProfile{}, db: map[int64]model.DBProfile{}, pairs: map[int64]model.KeyPair{}, stopAfter: 1024}
}
func (s *countedResolution) resolver() *Resolver {
	return &Resolver{snapshot: func(ctx context.Context) (resolutionSnapshot, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return s, nil
	}}
}
func (s *countedResolution) Close() {
	s.closed = true
	s.closeCalls++
}
func (s *countedResolution) lookup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.metadata++
	if s.metadata > s.stopAfter {
		return errLookupStop
	}
	if s.afterMetadata != nil {
		s.afterMetadata(s.metadata)
	}
	return nil
}
func (s *countedResolution) GetSSHMetadata(ctx context.Context, id int64) (model.SSHProfile, error) {
	if err := s.lookup(ctx); err != nil {
		return model.SSHProfile{}, err
	}
	p, ok := s.ssh[id]
	if !ok {
		return model.SSHProfile{}, store.ErrNotFound
	}
	p.Password = nil
	p.ProxyPassword = nil
	return p, nil
}
func (s *countedResolution) GetDBMetadata(ctx context.Context, id int64) (model.DBProfile, error) {
	if err := s.lookup(ctx); err != nil {
		return model.DBProfile{}, err
	}
	p, ok := s.db[id]
	if !ok {
		return model.DBProfile{}, store.ErrNotFound
	}
	p.Password = nil
	return p, nil
}
func (s *countedResolution) HasPrivateKey(ctx context.Context, id int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.keyMetadata++
	p, ok := s.pairs[id]
	if !ok {
		return false, store.ErrNotFound
	}
	return p.PrivateKey != nil, nil
}
func (s *countedResolution) decrypt(blob []byte, aad string) ([]byte, error) {
	if blob == nil {
		return nil, nil
	}
	s.decrypts = append(s.decrypts, aad)
	plain, err := s.codec.Decrypt(blob, []byte(aad))
	if s.afterDecrypt != nil {
		s.afterDecrypt(aad)
	}
	return plain, err
}
func (s *countedResolution) GetSSH(ctx context.Context, id int64) (model.SSHProfile, error) {
	s.secretLoadAttempts = append(s.secretLoadAttempts, fmt.Sprintf("ssh/%d", id))
	if err := ctx.Err(); err != nil {
		return model.SSHProfile{}, err
	}
	s.secretLoads++
	defer s.secretLoadFinished()
	p := s.ssh[id]
	var err error
	p.Password, err = s.decrypt(p.Password, fmt.Sprintf("warden/ssh/%d/password", id))
	if err != nil {
		return model.SSHProfile{}, err
	}
	p.ProxyPassword, err = s.decrypt(p.ProxyPassword, fmt.Sprintf("warden/ssh/%d/proxy_password", id))
	return p, err
}
func (s *countedResolution) GetDB(ctx context.Context, id int64) (model.DBProfile, error) {
	s.secretLoadAttempts = append(s.secretLoadAttempts, fmt.Sprintf("db/%d", id))
	if err := ctx.Err(); err != nil {
		return model.DBProfile{}, err
	}
	s.secretLoads++
	defer s.secretLoadFinished()
	p := s.db[id]
	var err error
	p.Password, err = s.decrypt(p.Password, fmt.Sprintf("warden/db/%d/password", id))
	return p, err
}
func (s *countedResolution) GetKeyPair(ctx context.Context, id int64) (model.KeyPair, error) {
	s.secretLoadAttempts = append(s.secretLoadAttempts, fmt.Sprintf("key-pair/%d", id))
	if err := ctx.Err(); err != nil {
		return model.KeyPair{}, err
	}
	s.secretLoads++
	defer s.secretLoadFinished()
	p := s.pairs[id]
	var err error
	p.PrivateKey, err = s.decrypt(p.PrivateKey, fmt.Sprintf("warden/key-pair/%d/private_key", id))
	if err != nil {
		return model.KeyPair{}, err
	}
	p.PrivateKeyPassphrase, err = s.decrypt(p.PrivateKeyPassphrase, fmt.Sprintf("warden/key-pair/%d/private_key_passphrase", id))
	return p, err
}
func (s *countedResolution) secretLoadFinished() {
	if s.afterSecretLoad != nil {
		s.afterSecretLoad(s.secretLoads)
	}
}

func (s *countedResolution) addSSH(t *testing.T, id int64, route string) {
	t.Helper()
	blob, err := s.codec.Encrypt([]byte("synthetic password"), []byte(fmt.Sprintf("warden/ssh/%d/password", id)))
	if err != nil {
		t.Fatal(err)
	}
	s.ssh[id] = model.SSHProfile{ID: id, Name: fmt.Sprint(id), JumpConnectionIDs: route, Password: blob}
}
func repeatRoute(id int64, n int) string {
	if n == 0 {
		return "[]"
	}
	return "[" + strings.TrimSuffix(strings.Repeat(fmt.Sprintf("%d,", id), n), ",") + "]"
}
func requireNoSecrets(t *testing.T, s *countedResolution) {
	t.Helper()
	if s.secretLoads != 0 || len(s.decrypts) != 0 {
		t.Fatalf("secret loads=%d decrypt callbacks=%v", s.secretLoads, s.decrypts)
	}
	if !s.closed {
		t.Fatal("snapshot not closed")
	}
}
func requireGraphFailure(t *testing.T, err error) {
	t.Helper()
	var ge *GraphError
	if !errors.As(err, &ge) {
		t.Fatalf("want graph error, got %v", err)
	}
}

func TestResolveDuplicateDAGCumulativeBudgetCounts(t *testing.T) {
	s := newCountedResolution()
	s.addSSH(t, 1, "[]")
	// Depth 30 fits depth32, but unbounded expansion would exceed a billion.
	// Fake getter stops at 1025 lookups even if the resolver has no budget.
	for id := int64(2); id <= 30; id++ {
		s.addSSH(t, id, repeatRoute(id-1, 2))
	}
	b, err := s.resolver().ResolveSSHBundle(context.Background(), 30)
	if !errors.Is(err, ErrJumpBudgetExceeded) {
		t.Fatalf("budget failure=%v; lookups=%d", err, s.metadata)
	}
	requireGraphFailure(t, err)
	requireNoSecrets(t, s)
	if s.metadata != 1024 || b.Target.ID != 0 || len(b.Jumps) != 0 {
		t.Fatalf("lookups=%d partial jumps=%d", s.metadata, len(b.Jumps))
	}
}

func TestResolveBudgetPreservesOrderAndDuplicatesCounts(t *testing.T) {
	s := newCountedResolution()
	s.addSSH(t, 1, "[]")
	s.addSSH(t, 2, "[1]")
	s.addSSH(t, 3, "[2,1,2]")
	b, err := s.resolver().ResolveSSHBundle(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, n := range b.Jumps {
		ids = append(ids, n.ID)
		if string(n.Password) != "synthetic password" {
			t.Fatal("password not decrypted")
		}
	}
	if !reflect.DeepEqual(ids, []int64{1, 2, 1, 1, 2}) {
		t.Fatalf("order=%v", ids)
	}
	if s.metadata != 6 || s.secretLoads != 6 || len(s.decrypts) != 6 || !s.closed {
		t.Fatalf("counts=%d/%d/%v closed=%v", s.metadata, s.secretLoads, s.decrypts, s.closed)
	}
}

func TestResolveValidatedKeySecretsAndFailures(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprintf("corrupt=%v", corrupt), func(t *testing.T) {
			s := newCountedResolution()
			s.addSSH(t, 1, "[]")
			s.addSSH(t, 2, "[1,1]")
			private, err := s.codec.Encrypt([]byte("synthetic key"), []byte("warden/key-pair/1/private_key"))
			if err != nil {
				t.Fatal(err)
			}
			phrase, err := s.codec.Encrypt([]byte("synthetic phrase"), []byte("warden/key-pair/1/private_key_passphrase"))
			if err != nil {
				t.Fatal(err)
			}
			if corrupt {
				private = []byte("corrupt key")
			}
			s.pairs[1] = model.KeyPair{ID: 1, PrivateKey: private, PrivateKeyPassphrase: phrase}
			p := s.ssh[1]
			p.KeyPairID = 1
			p.Password = nil // Match stored password/key-pair exclusivity.
			s.ssh[1] = p
			b, err := s.resolver().ResolveSSHBundle(context.Background(), 2)
			if corrupt {
				var ge *GraphError
				if err == nil || errors.As(err, &ge) || b.Target.ID != 0 || len(b.Jumps) != 0 {
					t.Fatalf("corrupt validated key: %v", err)
				}
				if !reflect.DeepEqual(s.decrypts, []string{"warden/ssh/2/password", "warden/key-pair/1/private_key"}) {
					t.Fatalf("actual failed decrypt callbacks=%v", s.decrypts)
				}
			} else {
				if err != nil || len(b.Jumps) != 2 {
					t.Fatalf("valid key: %v", err)
				}
				for _, hop := range b.Jumps {
					if string(hop.PrivateKey) != "synthetic key" || string(hop.PrivateKeyPassphrase) != "synthetic phrase" {
						t.Fatal("missing decrypted key")
					}
				}
				if len(s.decrypts) != 5 || s.secretLoads != 5 {
					t.Fatalf("secret loads=%d decrypt callbacks=%v", s.secretLoads, s.decrypts)
				}
			}
			if s.metadata != 3 || s.keyMetadata != 2 || !s.closed {
				t.Fatalf("validation counts=%d/%d", s.metadata, s.keyMetadata)
			}
		})
	}
}

// This characterizes already-correct production cancellation checks. Hooks
// cancel inside a secret getter, not during metadata validation. Attempts are
// recorded before the getter's context check so a later rejected call still
// fails the no-subsequent-load assertion.
func TestResolveSecretPhaseCancellation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		loads         []string
		decrypts      []string
		decryptsAtEnd []int
		metadata      int
		keyMetadata   int
	}{
		{
			name:          "ssh",
			loads:         []string{"ssh/3", "ssh/1", "ssh/2", "key-pair/1"},
			decrypts:      []string{"warden/ssh/3/password", "warden/ssh/1/password", "warden/key-pair/1/private_key", "warden/key-pair/1/private_key_passphrase"},
			decryptsAtEnd: []int{1, 2, 2, 4}, metadata: 3, keyMetadata: 1,
		},
		{
			name:  "direct-db",
			loads: []string{"db/1"}, decrypts: []string{"warden/db/1/password"},
			decryptsAtEnd: []int{1}, metadata: 1,
		},
		{
			name:          "tunneled-db",
			loads:         []string{"db/1", "ssh/3", "ssh/1", "ssh/2", "key-pair/1"},
			decrypts:      []string{"warden/db/1/password", "warden/ssh/3/password", "warden/ssh/1/password", "warden/key-pair/1/private_key", "warden/key-pair/1/private_key_passphrase"},
			decryptsAtEnd: []int{1, 2, 3, 3, 5}, metadata: 4, keyMetadata: 1,
		},
	} {
		for _, hook := range []string{"load", "decrypt"} {
			boundaries := len(tc.loads)
			if hook == "decrypt" {
				boundaries = len(tc.decrypts)
			}
			for at := 1; at <= boundaries; at++ {
				t.Run(fmt.Sprintf("%s/%s-%d", tc.name, hook, at), func(t *testing.T) {
					s := newCountedResolution()
					s.addSSH(t, 1, "[]")
					s.addSSH(t, 2, "[]")
					s.addSSH(t, 3, "[1,2]")
					private, err := s.codec.Encrypt([]byte("synthetic key"), []byte("warden/key-pair/1/private_key"))
					if err != nil {
						t.Fatal(err)
					}
					phrase, err := s.codec.Encrypt([]byte("synthetic phrase"), []byte("warden/key-pair/1/private_key_passphrase"))
					if err != nil {
						t.Fatal(err)
					}
					s.pairs[1] = model.KeyPair{ID: 1, PrivateKey: private, PrivateKeyPassphrase: phrase}
					p := s.ssh[2]
					p.Password, p.KeyPairID = nil, 1
					s.ssh[2] = p
					password, err := s.codec.Encrypt([]byte("synthetic db password"), []byte("warden/db/1/password"))
					if err != nil {
						t.Fatal(err)
					}
					db := model.DBProfile{ID: 1, Host: "db.invalid", Password: password, Databases: []model.DatabaseInfo{{Name: "app", IsDefault: true}}}
					if tc.name == "tunneled-db" {
						db.SSHConnectionID = 3
					}
					s.db[1] = db

					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					stopLoad := at
					if hook == "load" {
						s.afterSecretLoad = func(n int) {
							if n == at {
								cancel()
							}
						}
					} else {
						s.afterDecrypt = func(string) {
							if len(s.decrypts) == at {
								cancel()
							}
						}
						for i, end := range tc.decryptsAtEnd {
							if end >= at {
								stopLoad = i + 1
								break
							}
						}
					}
					if tc.name == "ssh" {
						b, e := s.resolver().ResolveSSHBundle(ctx, 3)
						err = e
						if !reflect.DeepEqual(b, model.SSHBundle{}) {
							t.Fatal("partial SSH bundle after secret cancellation")
						}
					} else {
						b, e := s.resolver().ResolveDBBundle(ctx, 1)
						err = e
						if !reflect.DeepEqual(b, model.DBBundle{}) {
							t.Fatal("partial DB bundle after secret cancellation")
						}
					}
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("secret-phase error=%v, want context.Canceled", err)
					}
					if s.secretLoads != stopLoad || !reflect.DeepEqual(s.secretLoadAttempts, tc.loads[:stopLoad]) {
						t.Fatalf("later load attempted: completed=%d attempts=%v, want %v", s.secretLoads, s.secretLoadAttempts, tc.loads[:stopLoad])
					}
					// A synchronous row already in progress may finish its remaining
					// fields (e.g. passphrase after private-key cancellation).
					if !reflect.DeepEqual(s.decrypts, tc.decrypts[:tc.decryptsAtEnd[stopLoad-1]]) {
						t.Fatalf("row decrypt callbacks=%v", s.decrypts)
					}
					if !s.closed || s.closeCalls != 1 || s.metadata != tc.metadata || s.keyMetadata != tc.keyMetadata {
						t.Fatalf("closure/validation counts: close=%d metadata=%d keys=%d", s.closeCalls, s.metadata, s.keyMetadata)
					}
					t.Logf("canceled: secret loads=%d attempts=%d decrypts=%d close=%d", s.secretLoads, len(s.secretLoadAttempts), len(s.decrypts), s.closeCalls)
				})
			}
		}
	}
}

func TestResolveBudgetBoundaryDepthAndCancellation(t *testing.T) {
	for _, db := range []bool{false, true} {
		for _, total := range []int{1024, 1025} {
			t.Run(fmt.Sprintf("db=%v/occurrences=%d", db, total), func(t *testing.T) {
				s := newCountedResolution()
				s.addSSH(t, 1, "[]")
				hops := total - 1
				if db {
					hops--
				}
				s.addSSH(t, 2, repeatRoute(1, hops))
				var err error
				var output int
				if db {
					s.db[1] = model.DBProfile{ID: 1, SSHConnectionID: 2, Databases: []model.DatabaseInfo{{Name: "app", IsDefault: true}}}
					var b model.DBBundle
					b, err = s.resolver().ResolveDBBundle(context.Background(), 1)
					if b.SSH != nil {
						output = 2 + len(b.SSH.Jumps)
					}
				} else {
					var b model.SSHBundle
					b, err = s.resolver().ResolveSSHBundle(context.Background(), 2)
					if b.Target.ID != 0 {
						output = 1 + len(b.Jumps)
					}
				}
				if total == 1024 {
					if err != nil || output != 1024 || s.metadata != 1024 || !s.closed {
						t.Fatalf("boundary output=%d lookups=%d err=%v", output, s.metadata, err)
					}
				} else {
					if !errors.Is(err, ErrJumpBudgetExceeded) || output != 0 || s.metadata != 1024 {
						t.Fatalf("overflow output=%d lookups=%d err=%v", output, s.metadata, err)
					}
					requireNoSecrets(t, s)
				}
			})
		}
	}
	for _, depth := range []int{32, 33} {
		t.Run(fmt.Sprintf("depth=%d", depth), func(t *testing.T) {
			s := newCountedResolution()
			s.addSSH(t, 1, "[]")
			for id := 2; id <= depth; id++ {
				s.addSSH(t, int64(id), fmt.Sprintf("[%d]", id-1))
			}
			b, err := s.resolver().ResolveSSHBundle(context.Background(), int64(depth))
			if depth == 32 {
				if err != nil || len(b.Jumps) != 31 {
					t.Fatalf("depth boundary: %v", err)
				}
			} else {
				if !errors.Is(err, ErrJumpDepthExceeded) || s.metadata != 32 {
					t.Fatalf("depth overflow lookups=%d err=%v", s.metadata, err)
				}
				requireNoSecrets(t, s)
			}
		})
	}
	for _, at := range []int{0, 1, 19, 1024} {
		t.Run(fmt.Sprintf("cancel-after=%d", at), func(t *testing.T) {
			s := newCountedResolution()
			s.addSSH(t, 1, "[]")
			s.addSSH(t, 2, repeatRoute(1, 1023))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if at == 0 {
				cancel()
			} else {
				s.afterMetadata = func(n int) {
					if n == at {
						cancel()
					}
				}
			}
			b, err := s.resolver().ResolveSSHBundle(ctx, 2)
			if !errors.Is(err, context.Canceled) || s.metadata != at || b.Target.ID != 0 || len(b.Jumps) != 0 {
				t.Fatalf("cancel err=%v lookups=%d jumps=%d", err, s.metadata, len(b.Jumps))
			}
			if at == 0 {
				if s.secretLoads != 0 || len(s.decrypts) != 0 {
					t.Fatal("pre-cancel decrypt")
				}
			} else {
				requireNoSecrets(t, s)
			}
		})
	}
}

func TestResolveDBBudgetCancellation(t *testing.T) {
	for _, at := range []int{0, 1, 2, 19, 1024} {
		t.Run(fmt.Sprintf("after=%d", at), func(t *testing.T) {
			s := newCountedResolution()
			s.addSSH(t, 1, "[]")
			s.addSSH(t, 2, repeatRoute(1, 1022))
			s.db[1] = model.DBProfile{ID: 1, SSHConnectionID: 2, Databases: []model.DatabaseInfo{{Name: "app", IsDefault: true}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if at == 0 {
				cancel()
			} else {
				s.afterMetadata = func(n int) {
					if n == at {
						cancel()
					}
				}
			}
			b, err := s.resolver().ResolveDBBundle(ctx, 1)
			if !errors.Is(err, context.Canceled) || s.metadata != at || b.SSH != nil || b.Host != "" {
				t.Fatalf("cancellation err=%v lookups=%d", err, s.metadata)
			}
			if at != 0 {
				requireNoSecrets(t, s)
			} else if s.secretLoads != 0 || len(s.decrypts) != 0 {
				t.Fatal("pre-cancel decrypt")
			}
		})
	}
}

func TestResolveInvalidGraphBeforeAnySecretDecryptCounts(t *testing.T) {
	for _, kind := range []string{"missing", "archived-target", "archived-hop", "cycle", "depth", "malformed", "key-missing", "key-cleared", "db-missing", "db-archived-target", "db-archived-hop", "db-cycle", "db-archived"} {
		t.Run(kind, func(t *testing.T) {
			s := newCountedResolution()
			s.addSSH(t, 1, "[]")
			s.addSSH(t, 2, "[1,999]")
			p := s.ssh[2]
			p.Password = []byte("corrupt password")
			s.ssh[2] = p
			// An earlier reachable key with corrupt ciphertext must not decrypt before
			// a later structural failure, including absent/cleared key references.
			s.pairs[1] = model.KeyPair{ID: 1, PrivateKey: []byte("corrupt private key"), PrivateKeyPassphrase: []byte("corrupt passphrase")}
			p = s.ssh[1]
			p.KeyPairID = 1
			p.Password = nil
			s.ssh[1] = p
			switch kind {
			case "archived-target", "db-archived-target":
				p = s.ssh[2]
				p.Archived = true
				s.ssh[2] = p
			case "archived-hop", "db-archived-hop":
				p = s.ssh[1]
				p.Archived = true
				s.ssh[1] = p
			case "cycle", "db-cycle":
				p = s.ssh[1]
				p.JumpConnectionIDs = "[2]"
				s.ssh[1] = p
			case "malformed":
				p = s.ssh[2]
				p.JumpConnectionIDs = `["secret-route-marker"]`
				s.ssh[2] = p
			case "depth":
				for id := int64(3); id <= 34; id++ {
					s.addSSH(t, id, fmt.Sprintf("[%d]", id-1))
				}
			case "key-missing", "key-cleared":
				p = s.ssh[2]
				p.JumpConnectionIDs = "[1]"
				s.ssh[2] = p
				if kind == "key-missing" {
					delete(s.pairs, 1)
				} else {
					s.pairs[1] = model.KeyPair{ID: 1}
				}
			}
			var err error
			if strings.HasPrefix(kind, "db-") {
				s.db[1] = model.DBProfile{ID: 1, SSHConnectionID: 2, Password: []byte("corrupt DB password"), Databases: []model.DatabaseInfo{{Name: "app", IsDefault: true}}, Archived: kind == "db-archived"}
				b, e := s.resolver().ResolveDBBundle(context.Background(), 1)
				err = e
				if b.Host != "" || b.SSH != nil {
					t.Fatal("partial DB bundle")
				}
			} else {
				id := int64(2)
				if kind == "depth" {
					id = 34
				}
				b, e := s.resolver().ResolveSSHBundle(context.Background(), id)
				err = e
				if b.Target.ID != 0 || len(b.Jumps) != 0 {
					t.Fatal("partial SSH bundle")
				}
			}
			if strings.Contains(kind, "archived") {
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("archive error=%v", err)
				}
			} else {
				requireGraphFailure(t, err)
			}
			if strings.Contains(fmt.Sprint(err), "secret-route-marker") {
				t.Fatal("raw route leaked")
			}
			requireNoSecrets(t, s)
		})
	}
}
