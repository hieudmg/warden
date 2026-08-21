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

// MaxJumpDepth bounds the number of nodes in a resolved jump route path
// (target plus hop chain).
const MaxJumpDepth = 32

// ErrJumpDepthExceeded reports a jump route deeper than MaxJumpDepth.
var ErrJumpDepthExceeded = errors.New("jump route exceeds the maximum depth")

// GraphError reports a logically invalid jump route: missing references,
// self-reference, cycles, malformed stored JSON, or depth overflow. It is
// distinct from storage/decryption failures so handlers can map it to a
// stable 422 invalid_graph response.
type GraphError struct {
	msg   string
	cause error
}

func (e *GraphError) Error() string { return e.msg }

// Unwrap exposes the wrapped sentinel (e.g. ErrJumpDepthExceeded) so
// callers can classify the specific graph failure with errors.Is.
func (e *GraphError) Unwrap() error { return e.cause }

func graphErrorf(format string, args ...any) error {
	return &GraphError{msg: fmt.Sprintf(format, args...)}
}

func graphErrorWrap(cause error, format string, args ...any) error {
	return &GraphError{msg: fmt.Sprintf(format, args...), cause: cause}
}

// Resolver resolves connection profiles into complete transport bundles,
// validating the full jump graph before any secret is returned.
type Resolver struct {
	store *store.Store
}

func NewResolver(s *store.Store) *Resolver { return &Resolver{store: s} }

// ResolveSSHBundle returns the target profile plus every jump host in
// connection order (first hop first). It validates the complete graph —
// missing ids, self-reference, cycles, malformed stored JSON, and depth —
// before decrypting and returning any secrets. On failure it returns no
// partial bundle.
func (r *Resolver) ResolveSSHBundle(ctx context.Context, id int64) (model.SSHBundle, error) {
	target, err := r.store.GetSSH(ctx, id)
	if err != nil {
		return model.SSHBundle{}, err
	}

	var jumps []model.SSHNode
	path := map[int64]bool{id: true}
	if err := r.resolveJumps(ctx, id, target.JumpConnectionIDs, path, &jumps); err != nil {
		return model.SSHBundle{}, err
	}
	if jumps == nil {
		jumps = []model.SSHNode{}
	}

	return model.SSHBundle{Target: sshNode(target), Jumps: jumps}, nil
}

// resolveJumps appends the ordered hop chain for ownerID's jump route to
// hops. path tracks the ids currently being resolved so cycles (including a
// route that loops back to the target) are detected.
func (r *Resolver) resolveJumps(ctx context.Context, ownerID int64, jumpJSON string, path map[int64]bool, hops *[]model.SSHNode) error {
	ids, err := parseJumpIDs(jumpJSON)
	if err != nil {
		return graphErrorf("connection %d has a malformed jump route: %v", ownerID, err)
	}
	for _, jid := range ids {
		if jid == ownerID {
			return graphErrorf("connection %d references itself in its jump route", ownerID)
		}
		if path[jid] {
			return graphErrorf("jump route cycle detected at connection %d", jid)
		}
		if len(path) >= MaxJumpDepth {
			return graphErrorWrap(ErrJumpDepthExceeded, "jump route exceeds the maximum depth of %d", MaxJumpDepth)
		}
		node, err := r.store.GetSSH(ctx, jid)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return graphErrorf("jump connection %d referenced by connection %d does not exist", jid, ownerID)
			}
			return err
		}
		path[jid] = true
		if err := r.resolveJumps(ctx, jid, node.JumpConnectionIDs, path, hops); err != nil {
			return err
		}
		*hops = append(*hops, sshNode(node))
		delete(path, jid)
	}
	return nil
}

// ResolveDBBundle returns the DB profile credentials plus, when the profile
// references an SSH connection, the complete resolved SSH bundle used to
// tunnel to the database.
func (r *Resolver) ResolveDBBundle(ctx context.Context, id int64) (model.DBBundle, error) {
	db, err := r.store.GetDB(ctx, id)
	if err != nil {
		return model.DBBundle{}, err
	}
	bundle := model.DBBundle{
		Host:     db.Host,
		Port:     db.Port,
		Username: db.Username,
		Password: db.Password,
		Database: db.Database,
	}
	if db.SSHConnectionID != 0 {
		sshBundle, err := r.ResolveSSHBundle(ctx, db.SSHConnectionID)
		if err != nil {
			return model.DBBundle{}, err
		}
		bundle.SSH = &sshBundle
	}
	return bundle, nil
}

func sshNode(p model.SSHProfile) model.SSHNode {
	return model.SSHNode{
		ID:                   p.ID,
		Name:                 p.Name,
		Host:                 p.Host,
		Port:                 p.Port,
		Username:             p.Username,
		Password:             p.Password,
		PrivateKey:           p.PrivateKey,
		PrivateKeyPassphrase: p.PrivateKeyPassphrase,
		ProxyHost:            p.ProxyHost,
		ProxyPort:            p.ProxyPort,
		ProxyUsername:        p.ProxyUsername,
		ProxyPassword:        p.ProxyPassword,
		DefaultDir:           p.DefaultDir,
	}
}

// parseJumpIDs parses a stored jump_connection_ids value. Rows are written
// through store validation, so a parse failure here indicates external
// tampering and is treated as a graph error. Negative ids can never name a
// real row and are rejected as missing references.
func parseJumpIDs(s string) ([]int64, error) {
	var ids []int64
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&ids); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("jump route must contain a single JSON array")
	}
	for _, id := range ids {
		if id < 0 {
			return nil, fmt.Errorf("jump id %d must not be negative", id)
		}
	}
	return ids, nil
}
