package profiles

import (
	"encoding/json"
	"errors"
	"io"
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

	mux.HandleFunc("GET /api/v1/transport/ssh/{id}", h.transportSSH)
	mux.HandleFunc("GET /api/v1/transport/db/{id}", h.transportDB)
}

func (h *Handler) listSSH(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.store.ListSSH(r.Context())
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "ssh_connection.list", "ssh_connection", "", "failure", err, nil)
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "list ssh connections failed")
		return
	}
	resp := make([]model.SSHConnection, 0, len(profiles))
	for _, p := range profiles {
		resp = append(resp, redactSSH(p))
	}
	h.audit.RecordRequest(r.Context(), r, "ssh_connection.list", "ssh_connection", "", "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) createSSH(w http.ResponseWriter, r *http.Request) {
	var req model.SSHConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.audit.RecordRequest(r.Context(), r, "ssh_connection.create", "ssh_connection", "", "failure", err, nil)
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
	}
	if req.Password != nil {
		p.Password = []byte(*req.Password)
	}
	if req.PrivateKey != nil {
		p.PrivateKey = []byte(*req.PrivateKey)
	}
	if req.PrivateKeyPassphrase != nil {
		p.PrivateKeyPassphrase = []byte(*req.PrivateKeyPassphrase)
	}
	if req.ProxyPassword != nil {
		p.ProxyPassword = []byte(*req.ProxyPassword)
	}

	created, err := h.store.CreateSSH(r.Context(), p)
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "ssh_connection.create", "ssh_connection", "", "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "ssh_connection.create", "ssh_connection", strconv.FormatInt(created.ID, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusCreated, redactSSH(created))
}

func (h *Handler) getSSH(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetSSH(r.Context(), id)
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "ssh_connection.get", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "ssh_connection.get", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactSSH(p))
}

func (h *Handler) updateSSH(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req model.SSHConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.audit.RecordRequest(r.Context(), r, "ssh_connection.update", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
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
	}
	if req.Password != nil {
		p.Password = []byte(*req.Password)
	}
	if req.PrivateKey != nil {
		p.PrivateKey = []byte(*req.PrivateKey)
	}
	if req.PrivateKeyPassphrase != nil {
		p.PrivateKeyPassphrase = []byte(*req.PrivateKeyPassphrase)
	}
	if req.ProxyPassword != nil {
		p.ProxyPassword = []byte(*req.ProxyPassword)
	}

	if err := h.store.UpdateSSH(r.Context(), p); err != nil {
		h.audit.RecordRequest(r.Context(), r, "ssh_connection.update", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	updated, err := h.store.GetSSH(r.Context(), id)
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "ssh_connection.update", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "ssh_connection.update", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactSSH(updated))
}

func (h *Handler) deleteSSH(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteSSH(r.Context(), id); err != nil {
		h.audit.RecordRequest(r.Context(), r, "ssh_connection.delete", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "ssh_connection.delete", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) sshDependents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	deps, err := h.store.SSHDependents(r.Context(), id)
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "ssh_connection.dependents", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "list ssh dependents failed")
		return
	}
	h.audit.RecordRequest(r.Context(), r, "ssh_connection.dependents", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, model.DependentsResponse{
		SSH: nonNilRefs(deps.SSH),
		DB:  nonNilRefs(deps.DB),
	})
}

func (h *Handler) listDB(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.store.ListDB(r.Context())
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "db_connection.list", "db_connection", "", "failure", err, nil)
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "list db connections failed")
		return
	}
	resp := make([]model.DBConnection, 0, len(profiles))
	for _, p := range profiles {
		resp = append(resp, redactDB(p))
	}
	h.audit.RecordRequest(r.Context(), r, "db_connection.list", "db_connection", "", "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) createDB(w http.ResponseWriter, r *http.Request) {
	var req model.DBConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.audit.RecordRequest(r.Context(), r, "db_connection.create", "db_connection", "", "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	p := model.DBProfile{
		Name:            req.Name,
		Host:            req.Host,
		Port:            req.Port,
		Username:        req.Username,
		Database:        req.Database,
		SSHConnectionID: req.SSHConnectionID,
	}
	if req.Password != nil {
		p.Password = []byte(*req.Password)
	}

	created, err := h.store.CreateDB(r.Context(), p)
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "db_connection.create", "db_connection", "", "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "db_connection.create", "db_connection", strconv.FormatInt(created.ID, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusCreated, redactDB(created))
}

func (h *Handler) getDB(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetDB(r.Context(), id)
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "db_connection.get", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "db_connection.get", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactDB(p))
}

func (h *Handler) updateDB(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req model.DBConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.audit.RecordRequest(r.Context(), r, "db_connection.update", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	p := model.DBProfile{
		ID:              id,
		Name:            req.Name,
		Host:            req.Host,
		Port:            req.Port,
		Username:        req.Username,
		Database:        req.Database,
		SSHConnectionID: req.SSHConnectionID,
	}
	if req.Password != nil {
		p.Password = []byte(*req.Password)
	}

	if err := h.store.UpdateDB(r.Context(), p); err != nil {
		h.audit.RecordRequest(r.Context(), r, "db_connection.update", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	updated, err := h.store.GetDB(r.Context(), id)
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "db_connection.update", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "db_connection.update", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactDB(updated))
}

func (h *Handler) deleteDB(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteDB(r.Context(), id); err != nil {
		h.audit.RecordRequest(r.Context(), r, "db_connection.delete", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "db_connection.delete", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// dbDependents always returns empty arrays: nothing in the schema references
// db_connections. The route exists to keep the API surface uniform.
func (h *Handler) dbDependents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	h.audit.RecordRequest(r.Context(), r, "db_connection.dependents", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, model.DependentsResponse{SSH: []model.DependentRef{}, DB: []model.DependentRef{}})
}

func (h *Handler) transportSSH(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	bundle, err := h.resolver.ResolveSSHBundle(r.Context(), id)
	if err != nil {
		h.audit.RecordRequest(r.Context(), r, "transport.ssh.get", "ssh_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeTransportError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "transport.ssh.get", "ssh_connection", strconv.FormatInt(id, 10), "success", nil, nil)
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
		h.audit.RecordRequest(r.Context(), r, "transport.db.get", "db_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeTransportError(w, err)
		return
	}
	h.audit.RecordRequest(r.Context(), r, "transport.db.get", "db_connection", strconv.FormatInt(id, 10), "success", nil, nil)
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
// fields, and exactly one JSON object.
func decodeStrict(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
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
		server.WriteError(w, http.StatusConflict, server.ErrConflict, "a connection with that name already exists")
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
		ID:                      p.ID,
		Name:                    p.Name,
		Host:                    p.Host,
		Port:                    p.Port,
		Username:                p.Username,
		HasPassword:             len(p.Password) > 0,
		HasPrivateKey:           len(p.PrivateKey) > 0,
		HasPrivateKeyPassphrase: len(p.PrivateKeyPassphrase) > 0,
		ProxyHost:               p.ProxyHost,
		ProxyPort:               p.ProxyPort,
		ProxyUsername:           p.ProxyUsername,
		HasProxyPassword:        len(p.ProxyPassword) > 0,
		JumpConnectionIDs:       p.JumpConnectionIDs,
		CreatedAt:               p.CreatedAt,
		UpdatedAt:               p.UpdatedAt,
	}
}

func redactDB(p model.DBProfile) model.DBConnection {
	return model.DBConnection{
		ID:              p.ID,
		Name:            p.Name,
		Host:            p.Host,
		Port:            p.Port,
		Username:        p.Username,
		HasPassword:     len(p.Password) > 0,
		Database:        p.Database,
		SSHConnectionID: p.SSHConnectionID,
		CreatedAt:       p.CreatedAt,
		UpdatedAt:       p.UpdatedAt,
	}
}
