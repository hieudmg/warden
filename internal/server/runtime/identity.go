package runtime

import (
	"context"
	"encoding/json"
	"warden/internal/crypto"
	"warden/internal/server/setup"
)

func passkeyWrapper(i setup.Installation, id string) (crypto.Wrapper, bool) {
	for _, w := range i.Passkeys {
		if w.CredentialID == id {
			return w, true
		}
	}
	return crypto.Wrapper{}, false
}
func (p *Plane) current(ctx context.Context) (setup.Installation, error) {
	raw, err := p.store.Installation(ctx)
	if err != nil {
		return setup.Installation{}, err
	}
	return validateInstallation(raw, p.cfg)
}
func (p *Plane) updateIdentity(ctx context.Context, change func(*setup.Installation) error, revoked string, all bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	before, err := p.store.Installation(ctx)
	if err != nil {
		return err
	}
	i, err := validateInstallation(before, p.cfg)
	if err != nil {
		return err
	}
	if err = change(&i); err != nil {
		return err
	}
	i.Passkey = crypto.Wrapper{}
	if all {
		i.AuthorizationGeneration++
	}
	after, err := json.Marshal(i)
	if err != nil {
		return err
	}
	i, err = validateInstallation(after, p.cfg)
	if err != nil {
		return err
	}
	if err = p.store.CompareAndSwapInstallation(ctx, before, after, revoked, all); err != nil {
		return err
	}
	if all {
		for id, s := range p.recoveries {
			s.Completed = true
			p.recoveries[id] = s
		}
	}
	// Keep only immutable initialization data in p.install; never authorize from it.
	if revoked != "" || all {
		for id, g := range p.grants {
			if all || g.Credential == revoked {
				delete(p.grants, id)
			}
		}
		for id, c := range p.challenges {
			if all || c.Credential == revoked {
				delete(p.challenges, id)
			}
		}
		for id, e := range p.pending {
			if all || e.Credential != nil && crypto.Encode(e.Credential.ID) == revoked {
				delete(p.pending, id)
			}
		}
	}
	return nil
}
