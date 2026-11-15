package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"warden/internal/model"
	"warden/internal/store"
)

// MaxJumpDepth bounds SSH nodes in a single path, including the SSH target.
const MaxJumpDepth = 32

// MaxResolutionOccurrences bounds a COMPLETE resolution: the root plus every
// followed reference, including duplicates. A DB root and its SSH target/hops
// share this budget. Each occurrence is charged before lookup/recursion; key
// presence and secret loads are bounded by those validated occurrences.
const MaxResolutionOccurrences = 1024

// ErrJumpDepthExceeded reports a jump route deeper than MaxJumpDepth.
var ErrJumpDepthExceeded = errors.New("jump route exceeds the maximum depth")

// ErrJumpBudgetExceeded reports an expansion beyond MaxResolutionOccurrences.
var ErrJumpBudgetExceeded = errors.New("jump route exceeds the maximum resolution budget")

// GraphError reports invalid stored structure separately from storage/crypto
// failures. Messages contain only fixed text and numeric IDs, never route JSON.
// Handlers map these errors to stable 422 invalid_graph responses.
type GraphError struct {
	msg   string
	cause error
}

func (e *GraphError) Error() string { return e.msg }

// Unwrap permits errors.Is classification of depth and budget failures.
func (e *GraphError) Unwrap() error { return e.cause }

func graphErrorf(format string, args ...any) error {
	return &GraphError{msg: fmt.Sprintf(format, args...)}
}

func graphErrorWrap(cause error, format string, args ...any) error {
	return &GraphError{msg: fmt.Sprintf(format, args...), cause: cause}
}

type resolutionSnapshot interface {
	GetSSHMetadata(context.Context, int64) (model.SSHProfile, error)
	GetDBMetadata(context.Context, int64) (model.DBProfile, error)
	HasPrivateKey(context.Context, int64) (bool, error)
	GetSSH(context.Context, int64) (model.SSHProfile, error)
	GetDB(context.Context, int64) (model.DBProfile, error)
	GetKeyPair(context.Context, int64) (model.KeyPair, error)
	Close()
}

// Resolver validates all reachable structure before loading any secrets, using
// the same read snapshot for both phases. Route order and duplicates survive.
type Resolver struct {
	snapshot func(context.Context) (resolutionSnapshot, error)
}

func NewResolver(s *store.Store) *Resolver {
	return &Resolver{snapshot: func(ctx context.Context) (resolutionSnapshot, error) {
		return s.BeginResolution(ctx)
	}}
}

type sshReference struct {
	id        int64
	keyPairID int64
}

type resolution struct {
	snapshot    resolutionSnapshot
	occurrences int
	postorder   []sshReference
}

func (s *resolution) charge(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.occurrences >= MaxResolutionOccurrences {
		return graphErrorWrap(ErrJumpBudgetExceeded, "jump route exceeds the maximum resolution budget of %d occurrences", MaxResolutionOccurrences)
	}
	s.occurrences++
	return nil
}

// ResolveSSHBundle returns no partial bundle on structural, cancellation or
// secret-loading failure. Initial missing/archived targets remain not-found.
func (r *Resolver) ResolveSSHBundle(ctx context.Context, id int64) (model.SSHBundle, error) {
	if err := ctx.Err(); err != nil {
		return model.SSHBundle{}, err
	}
	snapshot, err := r.snapshot(ctx)
	if err != nil {
		return model.SSHBundle{}, err
	}
	defer snapshot.Close()
	s := resolution{snapshot: snapshot}
	if err = s.charge(ctx); err != nil {
		return model.SSHBundle{}, err
	}
	if err = s.validateSSH(ctx, id, 0, map[int64]bool{}); err != nil {
		return model.SSHBundle{}, err
	}
	if err = s.validateKeys(ctx); err != nil {
		return model.SSHBundle{}, err
	}
	return s.sshBundle(ctx)
}

// validateSSH visits an occurrence already charged by its caller.
func (s *resolution) validateSSH(ctx context.Context, id, ownerID int64, path map[int64]bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if path[id] {
		return graphErrorf("jump route cycle detected at connection %d", id)
	}
	if len(path) >= MaxJumpDepth {
		return graphErrorWrap(ErrJumpDepthExceeded, "jump route exceeds the maximum depth of %d", MaxJumpDepth)
	}
	p, err := s.snapshot.GetSSHMetadata(ctx, id)
	if err != nil {
		if ownerID != 0 && errors.Is(err, store.ErrNotFound) {
			return graphErrorf("jump connection %d referenced by connection %d does not exist", id, ownerID)
		}
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if p.Archived {
		return store.ErrNotFound
	}
	path[id] = true
	defer delete(path, id)
	if err = walkJumpIDs(ctx, p.JumpConnectionIDs, func(jid int64) error {
		if err := s.charge(ctx); err != nil {
			return err
		}
		return s.validateSSH(ctx, jid, id, path)
	}); err != nil {
		return err
	}
	s.postorder = append(s.postorder, sshReference{id: p.ID, keyPairID: p.KeyPairID})
	return nil
}

func (s *resolution) validateKeys(ctx context.Context) error {
	for _, p := range s.postorder {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p.keyPairID == 0 {
			continue
		}
		has, err := s.snapshot.HasPrivateKey(ctx, p.keyPairID)
		if errors.Is(err, store.ErrNotFound) {
			return graphErrorf("connection %d references deleted key pair %d", p.id, p.keyPairID)
		}
		if err != nil {
			return err
		}
		if !has {
			return graphErrorf("connection %d references key pair %d without a private key", p.id, p.keyPairID)
		}
	}
	return ctx.Err()
}

func (s *resolution) sshBundle(ctx context.Context) (model.SSHBundle, error) {
	// The target is last in postorder; existing secret construction loaded the
	// target first, then hops. Output order remains first-hop-first, with repeats.
	target, err := s.sshNode(ctx, s.postorder[len(s.postorder)-1].id)
	if err != nil {
		return model.SSHBundle{}, err
	}
	jumps := make([]model.SSHNode, 0, len(s.postorder)-1)
	for _, p := range s.postorder[:len(s.postorder)-1] {
		node, err := s.sshNode(ctx, p.id)
		if err != nil {
			return model.SSHBundle{}, err
		}
		jumps = append(jumps, node)
	}
	if err = ctx.Err(); err != nil {
		return model.SSHBundle{}, err
	}
	return model.SSHBundle{Target: target, Jumps: jumps}, nil
}

// ResolveDBBundle shares a single snapshot and occurrence budget with its SSH
// tunnel. Neither DB passwords nor SSH/key secrets load before full validation.
func (r *Resolver) ResolveDBBundle(ctx context.Context, id int64, databaseName ...string) (model.DBBundle, error) {
	if err := ctx.Err(); err != nil {
		return model.DBBundle{}, err
	}
	if len(databaseName) > 1 {
		return model.DBBundle{}, fmt.Errorf("%w: at most one database selector is allowed", store.ErrValidation)
	}
	selector := ""
	if len(databaseName) == 1 {
		selector = databaseName[0]
	}
	snapshot, err := r.snapshot(ctx)
	if err != nil {
		return model.DBBundle{}, err
	}
	defer snapshot.Close()
	s := resolution{snapshot: snapshot}
	if err = s.charge(ctx); err != nil {
		return model.DBBundle{}, err
	}
	db, err := snapshot.GetDBMetadata(ctx, id)
	if err != nil {
		return model.DBBundle{}, err
	}
	if err = ctx.Err(); err != nil {
		return model.DBBundle{}, err
	}
	if db.Archived {
		return model.DBBundle{}, store.ErrNotFound
	}
	selected, err := selectDatabase(db.Databases, selector)
	if err != nil {
		return model.DBBundle{}, err
	}
	if db.SSHConnectionID != 0 {
		if err = s.charge(ctx); err != nil {
			return model.DBBundle{}, err
		}
		if err = s.validateSSH(ctx, db.SSHConnectionID, 0, map[int64]bool{}); err != nil {
			return model.DBBundle{}, err
		}
		if err = s.validateKeys(ctx); err != nil {
			return model.DBBundle{}, err
		}
	}
	if err = ctx.Err(); err != nil {
		return model.DBBundle{}, err
	}
	db, err = snapshot.GetDB(ctx, id)
	if err != nil {
		return model.DBBundle{}, err
	}
	bundle := model.DBBundle{
		Host:     db.Host,
		Port:     db.Port,
		Username: db.Username,
		Password: db.Password,
		Database: selected,
	}
	if db.SSHConnectionID != 0 {
		sshBundle, err := s.sshBundle(ctx)
		if err != nil {
			return model.DBBundle{}, err
		}
		bundle.SSH = &sshBundle
	}
	if err = ctx.Err(); err != nil {
		return model.DBBundle{}, err
	}
	return bundle, nil
}

func selectDatabase(databases []model.DatabaseInfo, selector string) (string, error) {
	if selector != "" {
		for _, database := range databases {
			if database.Name == selector {
				return database.Name, nil
			}
		}
		return "", fmt.Errorf("%w: database %q not found", store.ErrValidation, selector)
	}
	for _, database := range databases {
		if database.IsDefault {
			return database.Name, nil
		}
	}
	return "", fmt.Errorf("%w: database profile has no default database", store.ErrValidation)
}

func (s *resolution) sshNode(ctx context.Context, id int64) (model.SSHNode, error) {
	if err := ctx.Err(); err != nil {
		return model.SSHNode{}, err
	}
	p, err := s.snapshot.GetSSH(ctx, id)
	if err != nil {
		return model.SSHNode{}, err
	}
	node := model.SSHNode{
		ID:            p.ID,
		Name:          p.Name,
		Host:          p.Host,
		Port:          p.Port,
		Username:      p.Username,
		Password:      p.Password,
		ProxyHost:     p.ProxyHost,
		ProxyPort:     p.ProxyPort,
		ProxyUsername: p.ProxyUsername,
		ProxyPassword: p.ProxyPassword,
		DefaultDir:    p.DefaultDir,
	}
	if p.KeyPairID == 0 {
		return node, nil
	}
	if err = ctx.Err(); err != nil {
		return model.SSHNode{}, err
	}
	pair, err := s.snapshot.GetKeyPair(ctx, p.KeyPairID)
	if err != nil {
		return model.SSHNode{}, err
	}
	if len(pair.PrivateKey) == 0 {
		return model.SSHNode{}, graphErrorf("connection %d references key pair %d without a private key", p.ID, p.KeyPairID)
	}
	node.PrivateKey = pair.PrivateKey
	node.PrivateKeyPassphrase = pair.PrivateKeyPassphrase
	return node, nil
}

// walkJumpIDs streams the stored array instead of allocating a potentially
// enormous duplicate-edge slice before enforcing the budget. Each visitor
// charges before recursion/lookup. Parsing failures never expose stored values.
func walkJumpIDs(ctx context.Context, raw string, visit func(int64) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('[') {
		return graphErrorf("connection has a malformed jump route")
	}
	for dec.More() {
		if err = ctx.Err(); err != nil {
			return err
		}
		var id int64
		if err = dec.Decode(&id); err != nil || id < 0 {
			return graphErrorf("connection has a malformed jump route")
		}
		if err = visit(id); err != nil {
			return err
		}
	}
	if _, err = dec.Token(); err != nil {
		return graphErrorf("connection has a malformed jump route")
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return graphErrorf("connection has a malformed jump route")
	}
	return ctx.Err()
}
