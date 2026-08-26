package profiles

import (
	"net/http"
	"strconv"

	"warden/internal/model"
	"warden/internal/server"
)

// keyPairSummaryResponse is the list/CRUD mapper that keeps vault material
// out of non-GET payloads: KeyPairSummary carries presence flags only, so
// secret bytes never reach the JSON encoder outside the vault GET.
func keyPairSummaryResponse(p model.KeyPairSummary) model.KeyPairSummary {
	return p
}

// keyPairSummaryOf derives a redacted summary from a decrypted domain pair
// for create/update responses. Only presence is reported; raw values never
// leave the handler on non-GET endpoints.
func keyPairSummaryOf(p model.KeyPair) model.KeyPairSummary {
	return model.KeyPairSummary{
		ID:                      p.ID,
		Name:                    p.Name,
		HasPublicKey:            len(p.PublicKey) > 0,
		HasPrivateKey:           len(p.PrivateKey) > 0,
		HasPrivateKeyPassphrase: len(p.PrivateKeyPassphrase) > 0,
		CreatedAt:               p.CreatedAt,
		UpdatedAt:               p.UpdatedAt,
	}
}

// keyPairVaultResponse is the only mapping that converts stored bytes to
// strings. The individual vault GET is the sole endpoint that discloses key
// material, per the accepted-risk design.
func keyPairVaultResponse(p model.KeyPair) model.KeyPairVault {
	return model.KeyPairVault{
		ID:                   p.ID,
		Name:                 p.Name,
		PublicKey:            string(p.PublicKey),
		PrivateKey:           string(p.PrivateKey),
		PrivateKeyPassphrase: string(p.PrivateKeyPassphrase),
		CreatedAt:            p.CreatedAt,
		UpdatedAt:            p.UpdatedAt,
	}
}

func (h *Handler) listKeyPairs(w http.ResponseWriter, r *http.Request) {
	pairs, err := h.store.ListKeyPairs(r.Context())
	if err != nil {
		h.record(r, "key_pair.list", "key_pair", "", "failure", err, nil)
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "list key pairs failed")
		return
	}
	resp := make([]model.KeyPairSummary, 0, len(pairs))
	for _, p := range pairs {
		resp = append(resp, keyPairSummaryResponse(p))
	}
	h.record(r, "key_pair.list", "key_pair", "", "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) createKeyPair(w http.ResponseWriter, r *http.Request) {
	var req model.KeyPairRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "key_pair.create", "key_pair", "", "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	p := model.KeyPair{Name: req.Name}
	// Request pointers convert to []byte only when non-nil; nil means the
	// field was omitted (store SQL NULL on create).
	if req.PublicKey != nil {
		p.PublicKey = []byte(*req.PublicKey)
	}
	if req.PrivateKey != nil {
		p.PrivateKey = []byte(*req.PrivateKey)
	}
	if req.PrivateKeyPassphrase != nil {
		p.PrivateKeyPassphrase = []byte(*req.PrivateKeyPassphrase)
	}

	created, err := h.store.CreateKeyPair(r.Context(), p)
	if err != nil {
		h.record(r, "key_pair.create", "key_pair", "", "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "key_pair.create", "key_pair", strconv.FormatInt(created.ID, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusCreated, keyPairSummaryResponse(keyPairSummaryOf(created)))
}

func (h *Handler) getKeyPair(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetKeyPair(r.Context(), id)
	if err != nil {
		h.record(r, "key_pair.get", "key_pair", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "key_pair.get", "key_pair", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, keyPairVaultResponse(p))
}

func (h *Handler) updateKeyPair(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req model.KeyPairRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "key_pair.update", "key_pair", strconv.FormatInt(id, 10), "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	p := model.KeyPair{ID: id, Name: req.Name}
	if req.PublicKey != nil {
		p.PublicKey = []byte(*req.PublicKey)
	}
	if req.PrivateKey != nil {
		p.PrivateKey = []byte(*req.PrivateKey)
	}
	if req.PrivateKeyPassphrase != nil {
		p.PrivateKeyPassphrase = []byte(*req.PrivateKeyPassphrase)
	}

	if err := h.store.UpdateKeyPair(r.Context(), p); err != nil {
		h.record(r, "key_pair.update", "key_pair", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	updated, err := h.store.GetKeyPair(r.Context(), id)
	if err != nil {
		h.record(r, "key_pair.update", "key_pair", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "key_pair.update", "key_pair", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, keyPairSummaryResponse(keyPairSummaryOf(updated)))
}

func (h *Handler) deleteKeyPair(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteKeyPair(r.Context(), id); err != nil {
		h.record(r, "key_pair.delete", "key_pair", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "key_pair.delete", "key_pair", strconv.FormatInt(id, 10), "success", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// keyPairDependents lists SSH connections referencing the pair for deletion
// warnings. Deletion itself is never blocked; the pair row is removed and
// SSH references stay dangling.
func (h *Handler) keyPairDependents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	deps, err := h.store.KeyPairDependents(r.Context(), id)
	if err != nil {
		h.record(r, "key_pair.dependents", "key_pair", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "key_pair.dependents", "key_pair", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, model.DependentsResponse{
		SSH: nonNilRefs(deps),
		DB:  []model.DependentRef{},
	})
}
