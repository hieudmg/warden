package profiles

import (
	"net/http"
	"strconv"

	"warden/internal/model"
	"warden/internal/server"
)

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.store.ListGroups(r.Context())
	if err != nil {
		h.record(r, "group.list", "group", "", "failure", err, nil)
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "list groups failed")
		return
	}
	resp := make([]model.Group, 0, len(groups))
	resp = append(resp, groups...)
	h.record(r, "group.list", "group", "", "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	var req model.GroupRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "group.create", "group", "", "failure", err, nil)
		writeDecodeError(w, err)
		return
	}

	created, err := h.store.CreateGroup(r.Context(), model.Group{Name: req.Name})
	if err != nil {
		h.record(r, "group.create", "group", "", "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "group.create", "group", strconv.FormatInt(created.ID, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusCreated, created)
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	g, err := h.store.GetGroup(r.Context(), id)
	if err != nil {
		h.record(r, "group.get", "group", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "group.get", "group", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, g)
}

func (h *Handler) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req model.GroupRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "group.update", "group", strconv.FormatInt(id, 10), "failure", err, nil)
		writeDecodeError(w, err)
		return
	}

	if err := h.store.UpdateGroup(r.Context(), model.Group{ID: id, Name: req.Name}); err != nil {
		h.record(r, "group.update", "group", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	updated, err := h.store.GetGroup(r.Context(), id)
	if err != nil {
		h.record(r, "group.update", "group", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "group.update", "group", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, updated)
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteGroup(r.Context(), id); err != nil {
		h.record(r, "group.delete", "group", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "group.delete", "group", strconv.FormatInt(id, 10), "success", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) groupDependents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	deps, err := h.store.GroupDependents(r.Context(), id)
	if err != nil {
		h.record(r, "group.dependents", "group", strconv.FormatInt(id, 10), "failure", err, nil)
		writeStoreError(w, err)
		return
	}
	h.record(r, "group.dependents", "group", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, model.DependentsResponse{
		SSH: nonNilRefs(deps.SSH),
		DB:  nonNilRefs(deps.DB),
	})
}
