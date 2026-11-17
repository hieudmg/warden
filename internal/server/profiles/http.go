package profiles

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"warden/internal/model"
	"warden/internal/server"
	"warden/internal/store"
)

func (h *Handler) registerHTTP(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/http-connections", h.listHTTP)
	mux.HandleFunc("POST /api/v1/http-connections", h.createHTTP)
	mux.HandleFunc("GET /api/v1/http-connections/{id}", h.getHTTP)
	mux.HandleFunc("PUT /api/v1/http-connections/{id}", h.updateHTTP)
	mux.HandleFunc("DELETE /api/v1/http-connections/{id}", h.deleteHTTP)
	mux.HandleFunc("PUT /api/v1/http-connections/{id}/archive", func(w http.ResponseWriter, r *http.Request) { h.setArchive(w, r, "http") })
	mux.HandleFunc("POST /api/v1/http-connections/{id}/request", h.proxyHTTP)
}

func redactHTTP(p model.HTTPProfile) model.HTTPConnection {
	return model.HTTPConnection{
		ID: p.ID, Name: p.Name, Origin: p.Origin, AuthType: p.AuthType,
		Note: p.Note, GroupID: p.GroupID, GroupName: p.GroupName,
		HasCredential: len(p.Credential) > 0,
		HasUsername:   len(p.Username) > 0,
		HasPassword:   len(p.Password) > 0,
		Archived:      p.Archived, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}
func httpProfileFromRequest(id int64, r model.HTTPConnectionRequest) model.HTTPProfile {
	p := model.HTTPProfile{ID: id, Name: r.Name, Origin: r.Origin, AuthType: r.AuthType, Note: r.Note, GroupID: r.GroupID}
	if r.Credential != nil {
		p.Credential = []byte(*r.Credential)
	}
	if r.Username != nil {
		p.Username = []byte(*r.Username)
	}
	if r.Password != nil {
		p.Password = []byte(*r.Password)
	}
	return p
}
func (h *Handler) httpStoreError(w http.ResponseWriter, r *http.Request, op string, id int64, err error) {
	h.record(r, "http_connection."+op, "http_connection", strconv.FormatInt(id, 10), "failure", err, nil)
	writeStoreError(w, err)
}
func (h *Handler) listHTTP(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListHTTP(r.Context())
	if err != nil {
		h.httpStoreError(w, r, "list", 0, err)
		return
	}
	out := make([]model.HTTPConnection, 0, len(list))
	for _, p := range list {
		out = append(out, redactHTTP(p))
	}
	h.record(r, "http_connection.list", "http_connection", "", "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, out)
}
func (h *Handler) createHTTP(w http.ResponseWriter, r *http.Request) {
	var req model.HTTPConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "http_connection.create", "http_connection", "", "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	p, err := h.store.CreateHTTP(r.Context(), httpProfileFromRequest(0, req))
	if err != nil {
		h.httpStoreError(w, r, "create", 0, err)
		return
	}
	h.record(r, "http_connection.create", "http_connection", strconv.FormatInt(p.ID, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusCreated, redactHTTP(p))
}
func (h *Handler) getHTTP(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetHTTP(r.Context(), id)
	if err != nil {
		h.httpStoreError(w, r, "get", id, err)
		return
	}
	h.record(r, "http_connection.get", "http_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactHTTP(p))
}
func (h *Handler) updateHTTP(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req model.HTTPConnectionRequest
	if err := decodeStrict(w, r, &req); err != nil {
		h.record(r, "http_connection.update", "http_connection", strconv.FormatInt(id, 10), "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	if err := h.store.UpdateHTTP(r.Context(), httpProfileFromRequest(id, req)); err != nil {
		h.httpStoreError(w, r, "update", id, err)
		return
	}
	p, err := h.store.GetHTTP(r.Context(), id)
	if err != nil {
		h.httpStoreError(w, r, "update", id, err)
		return
	}
	h.record(r, "http_connection.update", "http_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	server.WriteJSON(w, http.StatusOK, redactHTTP(p))
}
func (h *Handler) deleteHTTP(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteHTTP(r.Context(), id); err != nil {
		h.httpStoreError(w, r, "delete", id, err)
		return
	}
	h.record(r, "http_connection.delete", "http_connection", strconv.FormatInt(id, 10), "success", nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), model.HTTPOperationTimeout)
	defer cancel()
	// Bound slow incoming body reads as well as upstream work. ResponseController
	// follows middleware Unwrap; deadlines are reset before connection reuse.
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline.Add(time.Second))
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(callbackDone); _ = controller.SetReadDeadline(time.Now()) })
	defer func() {
		if !stop() {
			<-callbackDone
		}
		// Flush while the write budget still applies. On a failed delivery or
		// cancellation leave the connection unusable rather than allowing the
		// server's final buffered flush/body drain to run without a deadline.
		if err := controller.Flush(); err != nil || ctx.Err() != nil {
			_ = controller.SetReadDeadline(time.Now())
			_ = controller.SetWriteDeadline(time.Now())
			return
		}
		_ = controller.SetReadDeadline(time.Time{})
		_ = controller.SetWriteDeadline(time.Time{})
	}()
	var req model.HTTPProxyRequest
	if err := decodeStrictLimit(w, r, &req, 2<<20); err != nil {
		writeDecodeError(w, err)
		return
	}
	if len(req.Body) > model.HTTPMaxRequestBytes {
		writeDecodeError(w, errPayloadTooLarge)
		return
	}
	if err := model.ValidateHTTPProxyRequest(req); err != nil {
		server.WriteError(w, http.StatusBadRequest, server.ErrInvalidRequest, err.Error())
		return
	}
	p, err := h.store.GetHTTP(ctx, id)
	if err == nil && p.Archived {
		err = store.ErrNotFound
	}
	if err != nil {
		h.httpStoreError(w, r, "request", id, err)
		return
	}
	// Revalidate at the execution boundary as imported/external rows must not
	// permit origin overrides. The credential modes are deliberately exclusive.
	if err := model.ValidateHTTPOrigin(p.Origin); err != nil {
		h.httpStoreError(w, r, "request", id, errors.New("invalid stored origin"))
		return
	}
	if (p.AuthType == "basic" && (len(p.Username) == 0 || len(p.Password) == 0)) || ((p.AuthType == "bearer" || p.AuthType == "x_api_key") && len(p.Credential) == 0) {
		server.WriteError(w, http.StatusBadRequest, server.ErrValidation, "HTTP profile credentials are incomplete")
		return
	}
	up, err := http.NewRequestWithContext(ctx, req.Method, p.Origin+req.Path, bytes.NewReader(req.Body))
	if err != nil {
		server.WriteError(w, http.StatusBadRequest, server.ErrInvalidRequest, "invalid upstream request")
		return
	}
	if req.ContentType != "" {
		up.Header.Set("Content-Type", req.ContentType)
	} else if req.Body != nil {
		up.Header.Set("Content-Type", "application/json")
	}
	switch p.AuthType {
	case "bearer":
		up.Header.Set("Authorization", "Bearer "+string(p.Credential))
	case "x_api_key":
		up.Header.Set("X-API-Key", string(p.Credential))
	case "basic":
		up.SetBasicAuth(string(p.Username), string(p.Password))
	default:
		server.WriteError(w, http.StatusBadRequest, server.ErrValidation, "invalid HTTP profile authentication")
		return
	}
	// A fresh transport, no Jar, no ambient proxy, and no reusable connections
	// prevent state or credentials crossing operations. TLS verification stays on.
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  model.HTTPOperationTimeout,
		MaxResponseHeaderBytes: 32 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(up)
	if err != nil {
		h.proxyError(w, r, id, ctx)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, model.HTTPMaxResponseBytes+1))
	if err != nil || ctx.Err() != nil || len(body) > model.HTTPMaxResponseBytes {
		h.proxyError(w, r, id, ctx)
		return
	}
	h.record(r, "http_connection.request", "http_connection", strconv.FormatInt(id, 10), "success", nil, map[string]any{"status_code": resp.StatusCode})
	server.WriteJSON(w, http.StatusOK, model.HTTPProxyResponse{StatusCode: resp.StatusCode, Body: body})
}

func (h *Handler) proxyError(w http.ResponseWriter, r *http.Request, id int64, ctx context.Context) {
	status := http.StatusBadGateway
	message := "upstream request failed"
	if ctx.Err() != nil {
		status = http.StatusGatewayTimeout
		message = "upstream request canceled or timed out"
	}
	h.record(r, "http_connection.request", "http_connection", strconv.FormatInt(id, 10), "failure", errors.New(message), nil)
	server.WriteError(w, status, server.ErrInternal, message)
}
