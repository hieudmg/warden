package server

import (
	"encoding/json"
	"net/http"
)

// Stable machine-readable error codes. Clients and the web UI switch on
// these codes, so they are part of the API contract and must not change.
const (
	ErrInvalidRequest   = "invalid_request"
	ErrValidation       = "validation_error"
	ErrNotFound         = "not_found"
	ErrConflict         = "conflict"
	ErrMethodNotAllowed = "method_not_allowed"
	ErrPayloadTooLarge  = "payload_too_large"
	ErrGraphInvalid     = "invalid_graph"
	ErrDecryption       = "decryption_failed"
	ErrInternal         = "internal_error"
)

// ErrorResponse is the stable JSON error envelope returned by the API.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteError writes a stable JSON error response. Messages are sanitized by
// callers and never contain credentials, SQL, or remote command text.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: code, Message: message})
}

// WriteJSON writes a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
