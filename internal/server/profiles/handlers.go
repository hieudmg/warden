package profiles

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"warden/internal/model"
	"warden/internal/server"
	"warden/internal/server/audit"
	"warden/internal/store"
)

// maxBodyBytes bounds API request bodies.
const maxBodyBytes = 1 << 20 // 1 MiB

var (
	errInvalidJSON     = errors.New("request body must be a single JSON object with known fields")
	errPayloadTooLarge = errors.New("request body exceeds the size limit")
)

// Handler serves the profile CRUD, dependent-warning, and transport routes.
type Handler struct {
	store    *store.Store
	resolver *Resolver
	audit    *audit.Recorder
}

func New(s *store.Store, a *audit.Recorder) *Handler {
	return &Handler{store: s, resolver: NewResolver(s), audit: a}
}

// record writes an audit event for an HTTP request and surfaces recorder
// failures as a server warning so audit loss is never silent. Only
// operation/resource identifiers and the sanitized recorder error are
// logged — never secrets, SQL text, or request bodies.
func (h *Handler) record(r *http.Request, op, resourceType, resourceID, result string, err error, metadata map[string]any) {
	if aerr := h.audit.RecordRequest(r.Context(), r, op, resourceType, resourceID, result, err, metadata); aerr != nil {
		slog.Warn("audit write failed",
			"op", op,
			"resource_type", resourceType,
			"resource_id", resourceID,
			"error", aerr,
		)
	}
}

// Register mounts all profile routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/ssh-connections", h.listSSH)
	mux.HandleFunc("POST /api/v1/ssh-connections", h.createSSH)
	mux.HandleFunc("GET /api/v1/ssh-connections/{id}", h.getSSH)
	mux.HandleFunc("PUT /api/v1/ssh-connections/{id}", h.updateSSH)
	mux.HandleFunc("DELETE /api/v1/ssh-connections/{id}", h.deleteSSH)
	mux.HandleFunc("GET /api/v1/ssh-connections/{id}/dependents", h.sshDependents)

	mux.HandleFunc("GET /api/v1/db-connections", h.listDB)
	mux.HandleFunc("POST /api/v1/db-connections", h.createDB)
	mux.HandleFunc("GET /api/v1/db-connections/{id}", h.getDB)
	mux.HandleFunc("PUT /api/v1/db-connections/{id}", h.updateDB)
	mux.HandleFunc("DELETE /api/v1/db-connections/{id}", h.deleteDB)
	mux.HandleFunc("GET /api/v1/db-connections/{id}/dependents", h.dbDependents)

	mux.HandleFunc("GET /api/v1/groups", h.listGroups)
	mux.HandleFunc("POST /api/v1/groups", h.createGroup)
	mux.HandleFunc("GET /api/v1/groups/{id}", h.getGroup)
	mux.HandleFunc("PUT /api/v1/groups/{id}", h.updateGroup)
	mux.HandleFunc("DELETE /api/v1/groups/{id}", h.deleteGroup)
	mux.HandleFunc("GET /api/v1/groups/{id}/dependents", h.groupDependents)

	mux.HandleFunc("GET /api/v1/key-pairs", h.listKeyPairs)
	mux.HandleFunc("POST /api/v1/key-pairs", h.createKeyPair)
	mux.HandleFunc("GET /api/v1/key-pairs/{id}", h.getKeyPair)
	mux.HandleFunc("PUT /api/v1/key-pairs/{id}", h.updateKeyPair)
	mux.HandleFunc("DELETE /api/v1/key-pairs/{id}", h.deleteKeyPair)
	mux.HandleFunc("GET /api/v1/key-pairs/{id}/dependents", h.keyPairDependents)

	mux.HandleFunc("GET /api/v1/transport/ssh/{id}", h.transportSSH)
	mux.HandleFunc("GET /api/v1/transport/db/{id}", h.transportDB)
}

func (h *Handler) listSSH(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.store.ListSSH(r.Context())
	if err != nil {
		h.record(r, "ssh_connection.list", "ssh_connection", "", "failure", err, nil)
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "list ssh connections failed")
		return
	}
	resp := make([]model.SSHConnection, 0, len(profiles))
	for _, p := range profiles {
		resp = append(resp, redactSSH(p))
	}
	h.record(r, "ssh_connection.list", "ssh_connection", "", "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) createSSH(w http.ResponseWriter, r *http.Request) {
	var req model.SSHConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "ssh_connection.create", "ssh_connection", "", "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	p := model.SSHProfile{
		Name:              req.Name,
		Host:              req.Host,
		Port:              req.Port,
		Username:          req.Username,
		ProxyHost:         req.ProxyHost,
		ProxyPort:         req.ProxyPort,
		ProxyUsername:     req.ProxyUsername,
		JumpConnectionIDs: req.JumpConnectionIDs,
		DefaultDir:        req.DefaultDir,
		GroupID:           req.GroupID,
	}
	if req.KeyPairID != nil {
		p.KeyPairID = *req.KeyPairID
		p.KeyPairIDSet = true
	}
	if req.Password != nil {
		p.Password = []byte(*req.Password)
	}
	if req.ProxyPassword != nil {
		p.ProxyPassword = []byte(*req.ProxyPassword)
	}

	created, err := h.store.CreateSSH(r.Context(), p)
	if err != nil {
		h.record(r, "ssh_connection.create", "ssh_connection", "", "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	// Re-read with the group join so the create response carries the
	// group_name the client needs to render the row immediately.
	created, err = h.store.GetSSH(r.Context(), created.ID)
	if err != nil {
		h.record(r, "ssh_connection.create", "ssh_connection", strconv.FormatInt(created.ID, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "ssh_connection.create", "ssh_connection", strconv.FormatInt(created.ID, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusCreated, redactSSH(created))
}

func (h *Handler) getSSH(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetSSH(r.Context(), id)
	if err != nil {
		h.record(r, "ssh_connection.get", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "ssh_connection.get", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactSSH(p))
}

func (h *Handler) updateSSH(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req model.SSHConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "ssh_connection.update", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	p := model.SSHProfile{
		ID:                id,
		Name:              req.Name,
		Host:              req.Host,
		Port:              req.Port,
		Username:          req.Username,
		ProxyHost:         req.ProxyHost,
		ProxyPort:         req.ProxyPort,
		ProxyUsername:     req.ProxyUsername,
		JumpConnectionIDs: req.JumpConnectionIDs,
		DefaultDir:        req.DefaultDir,
		GroupID:           req.GroupID,
	}
	if req.KeyPairID != nil {
		p.KeyPairID = *req.KeyPairID
		p.KeyPairIDSet = true
	}
	if req.Password != nil {
		p.Password = []byte(*req.Password)
	}
	if req.ProxyPassword != nil {
		p.ProxyPassword = []byte(*req.ProxyPassword)
	}

	if err := h.store.UpdateSSH(r.Context(), p); err != nil {
		h.record(r, "ssh_connection.update", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	updated, err := h.store.GetSSH(r.Context(), id)
	if err != nil {
		h.record(r, "ssh_connection.update", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "ssh_connection.update", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactSSH(updated))
}

func (h *Handler) deleteSSH(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteSSH(r.Context(), id); err != nil {
		h.record(r, "ssh_connection.delete", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "ssh_connection.delete", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) sshDependents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	deps, err := h.store.SSHDependents(r.Context(), id)
	if err != nil {
		h.record(r, "ssh_connection.dependents", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "list ssh dependents failed")
		return
	}
	h.record(r, "ssh_connection.dependents", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, model.DependentsResponse{
		SSH: nonNilRefs(deps.SSH),
		DB:  nonNilRefs(deps.DB),
	})
}

func (h *Handler) listDB(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.store.ListDB(r.Context())
	if err != nil {
		h.record(r, "db_connection.list", "db_connection", "", "failure", err, nil)
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "list db connections failed")
		return
	}
	resp := make([]model.DBConnection, 0, len(profiles))
	for _, p := range profiles {
		resp = append(resp, redactDB(p))
	}
	h.record(r, "db_connection.list", "db_connection", "", "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) createDB(w http.ResponseWriter, r *http.Request) {
	var req model.DBConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "db_connection.create", "db_connection", "", "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	p, err := dbProfileFromRequest(0, req)
	if err != nil {
		h.record(r, "db_connection.create", "db_connection", "", "failure", err, nil)
		writeStoreError(w, err)
		return
	}

	created, err := h.store.CreateDB(r.Context(), p)
	if err != nil {
		h.record(r, "db_connection.create", "db_connection", "", "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	// Fetch again with the JOIN so the response includes the group name.
	created, err = h.store.GetDB(r.Context(), created.ID)
	if err != nil {
		h.record(r, "db_connection.create", "db_connection", strconv.FormatInt(created.ID, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "db_connection.create", "db_connection", strconv.FormatInt(created.ID, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusCreated, redactDB(created))
}

func (h *Handler) getDB(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetDB(r.Context(), id)
	if err != nil {
		h.record(r, "db_connection.get", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "db_connection.get", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactDB(p))
}

func (h *Handler) updateDB(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req model.DBConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "db_connection.update", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	p, err := dbProfileFromRequest(id, req)
	if err != nil {
		h.record(r, "db_connection.update", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}

	if err := h.store.UpdateDB(r.Context(), p); err != nil {
		h.record(r, "db_connection.update", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	updated, err := h.store.GetDB(r.Context(), id)
	if err != nil {
		h.record(r, "db_connection.update", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "db_connection.update", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactDB(updated))
}

func (h *Handler) deleteDB(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteDB(r.Context(), id); err != nil {
		h.record(r, "db_connection.delete", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "db_connection.delete", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// dbDependents always returns empty arrays: nothing in the schema references
// db_connections. The route exists to keep the API surface uniform.
func (h *Handler) dbDependents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	h.record(r, "db_connection.dependents", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, model.DependentsResponse{SSH: []model.DependentRef{}, DB: []model.DependentRef{}})
}

func (h *Handler) transportSSH(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	bundle, err := h.resolver.ResolveSSHBundle(r.Context(), id)
	if err != nil {
		h.record(r, "transport.ssh.get", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeTransportError(w, err)
		return
	}
	h.record(r, "transport.ssh.get", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	w.Header().Set("Cache-Control", "no-store")
	server.WriteJSON(w, http.StatusOK, bundle)
}

func (h *Handler) transportDB(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	bundle, err := h.resolver.ResolveDBBundle(r.Context(), id)
	if err != nil {
		h.record(r, "transport.db.get", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeTransportError(w, err)
		return
	}
	h.record(r, "transport.db.get", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	w.Header().Set("Cache-Control", "no-store")
	server.WriteJSON(w, http.StatusOK, bundle)
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		server.WriteError(w, http.StatusBadRequest, server.ErrInvalidRequest, "id must be a positive integer")
		return 0, false
	}
	return id, true
}

// decodeStrict enforces a bounded body, strict JSON decoding with no unknown
// fields, and exactly one JSON object. The first JSON value must be an
// object: null, arrays, scalars, and strings are rejected.
func decodeStrict(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	br := bufio.NewReader(r.Body)
	// Peek past leading whitespace and require the first JSON value to be
	// an object before any decoding happens.
	for {
		b, err := br.Peek(1)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				return errPayloadTooLarge
			}
			return errInvalidJSON
		}
		if b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r' {
			if _, err := br.Discard(1); err != nil {
				return errInvalidJSON
			}
			continue
		}
		if b[0] != '{' {
			return errInvalidJSON
		}
		break
	}
	dec := json.NewDecoder(br)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errPayloadTooLarge
		}
		return errInvalidJSON
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errInvalidJSON
	}
	return nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errPayloadTooLarge) {
		server.WriteError(w, http.StatusRequestEntityTooLarge, server.ErrPayloadTooLarge, err.Error())
		return
	}
	server.WriteError(w, http.StatusBadRequest, server.ErrInvalidRequest, err.Error())
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		server.WriteError(w, http.StatusNotFound, server.ErrNotFound, "resource not found")
	case errors.Is(err, store.ErrDuplicate):
		server.WriteError(w, http.StatusConflict, server.ErrConflict, "a resource with that name already exists")
	case errors.Is(err, store.ErrValidation):
		server.WriteError(w, http.StatusBadRequest, server.ErrValidation, err.Error())
	default:
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "internal server error")
	}
}

func writeTransportError(w http.ResponseWriter, err error) {
	var graphErr *GraphError
	switch {
	case errors.Is(err, store.ErrNotFound):
		server.WriteError(w, http.StatusNotFound, server.ErrNotFound, "connection not found")
	case errors.As(err, &graphErr):
		server.WriteError(w, http.StatusUnprocessableEntity, server.ErrGraphInvalid, graphErr.Error())
	default:
		server.WriteError(w, http.StatusInternalServerError, server.ErrDecryption, "failed to resolve connection secrets")
	}
}

// nonNilRefs returns refs, or an empty slice when refs is nil so JSON
// responses marshal [] instead of null.
func nonNilRefs(refs []model.DependentRef) []model.DependentRef {
	if refs == nil {
		return []model.DependentRef{}
	}
	return refs
}

func redactSSH(p model.SSHProfile) model.SSHConnection {
	return model.SSHConnection{
		ID:                p.ID,
		Name:              p.Name,
		Host:              p.Host,
		Port:              p.Port,
		Username:          p.Username,
		HasPassword:       len(p.Password) > 0,
		KeyPairID:         p.KeyPairID,
		KeyPairName:       p.KeyPairName,
		ProxyHost:         p.ProxyHost,
		ProxyPort:         p.ProxyPort,
		ProxyUsername:     p.ProxyUsername,
		HasProxyPassword:  len(p.ProxyPassword) > 0,
		JumpConnectionIDs: p.JumpConnectionIDs,
		DefaultDir:        p.DefaultDir,
		GroupID:           p.GroupID,
		GroupName:         p.GroupName,
		CreatedAt:         p.CreatedAt,
		UpdatedAt:         p.UpdatedAt,
	}
}

func dbProfileFromRequest(id int64, req model.DBConnectionRequest) (model.DBProfile, error) {
	databases := req.Databases
	if len(databases) == 0 {
		if req.Database == "" {
			return model.DBProfile{}, fmt.Errorf("%w: database or databases must be provided", store.ErrValidation)
		}
		databases = []model.DatabaseInfo{{Name: req.Database, IsDefault: true}}
	} else if req.Database != "" {
		defaultName := ""
		for _, database := range databases {
			if database.IsDefault {
				if defaultName != "" {
					return model.DBProfile{}, fmt.Errorf("%w: database alias conflicts with multiple defaults", store.ErrValidation)
				}
				defaultName = database.Name
			}
		}
		if defaultName == "" || req.Database != defaultName {
			return model.DBProfile{}, fmt.Errorf("%w: database must match the default database entry", store.ErrValidation)
		}
	}

	p := model.DBProfile{
		ID:              id,
		Name:            req.Name,
		Host:            req.Host,
		Port:            req.Port,
		Username:        req.Username,
		Databases:       append([]model.DatabaseInfo(nil), databases...),
		SSHConnectionID: req.SSHConnectionID,
		GroupID:         req.GroupID,
	}
	if req.Password != nil {
		p.Password = []byte(*req.Password)
	}
	return p, nil
}

func redactDB(p model.DBProfile) model.DBConnection {
	databases := append([]model.DatabaseInfo(nil), p.Databases...)
	defaultName := ""
	for _, database := range databases {
		if database.IsDefault {
			defaultName = database.Name
			break
		}
	}
	return model.DBConnection{
		ID:              p.ID,
		Name:            p.Name,
		Host:            p.Host,
		Port:            p.Port,
		Username:        p.Username,
		HasPassword:     len(p.Password) > 0,
		Database:        defaultName,
		Databases:       databases,
		SSHConnectionID: p.SSHConnectionID,
		GroupID:         p.GroupID,
		GroupName:       p.GroupName,
		CreatedAt:       p.CreatedAt,
		UpdatedAt:       p.UpdatedAt,
	}
}
