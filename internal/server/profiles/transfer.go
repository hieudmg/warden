package profiles

import (
	"errors"
	"net/http"

	"warden/internal/model"
	"warden/internal/server"
	"warden/internal/store"
)

// maxTransferBodyBytes bounds the data-import body. A migration bundle carries
// every managed record with plaintext secrets, so it cannot fit the CRUD
// limit; the bound still caps how much memory one request can demand.
const maxTransferBodyBytes = 50 << 20 // 50 MiB

// transferFilename is the attachment name offered for an exported bundle. The
// file is plaintext, so clients must be warned before they keep it.
const transferFilename = "warden-data.json"

// exportData streams the complete managed dataset as a downloadable bundle.
// The response carries plaintext secrets, so it is never cacheable.
func (h *Handler) exportData(w http.ResponseWriter, r *http.Request) {
	bundle, err := h.store.ExportData(r.Context())
	if err != nil {
		h.record(r, "data.export", "data", "", "failure", err, nil)
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "export data failed")
		return
	}
	h.record(r, "data.export", "data", "", "success", nil, bundleCounts(bundle))
	w.Header().Set("Content-Disposition", `attachment; filename="`+transferFilename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	server.WriteJSON(w, http.StatusOK, bundle)
}

// importData restores one bundle into an empty destination. The store rejects a
// non-empty destination and rolls back every partial write, so a failed
// request never leaves managed data behind. The request body is never logged:
// it carries plaintext credentials.
func (h *Handler) importData(w http.ResponseWriter, r *http.Request) {
	// Set on every import response, including failures: neither a bundle nor a
	// rejection is safe to cache.
	w.Header().Set("Cache-Control", "no-store")

	var bundle model.DataBundle
	if err := decodeStrictLimit(w, r, &bundle, maxTransferBodyBytes); err != nil {
		h.record(r, "data.import", "data", "", "failure", err, nil)
		writeDecodeError(w, err)
		return
	}
	if err := h.store.ImportData(r.Context(), bundle); err != nil {
		h.record(r, "data.import", "data", "", "failure", err, nil)
		writeImportError(w, err)
		return
	}
	h.record(r, "data.import", "data", "", "success", nil, bundleCounts(bundle))
	w.WriteHeader(http.StatusNoContent)
}

// writeImportError maps store import failures to stable API envelopes. The
// conflict message is sanitized so internal table names never reach a client.
func writeImportError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrDestinationNotEmpty):
		server.WriteError(w, http.StatusConflict, server.ErrConflict, "destination already contains managed data")
	case errors.Is(err, store.ErrValidation):
		server.WriteError(w, http.StatusBadRequest, server.ErrValidation, err.Error())
	default:
		server.WriteError(w, http.StatusInternalServerError, server.ErrInternal, "import data failed")
	}
}

// bundleCounts reports how many records of each kind a bundle carries. Counts
// are safe audit metadata: they never include names, credentials, or contents.
func bundleCounts(b model.DataBundle) map[string]any {
	return map[string]any{
		"groups":           len(b.Groups),
		"key_pairs":        len(b.KeyPairs),
		"ssh_connections":  len(b.SSHConnections),
		"db_connections":   len(b.DBConnections),
		"projects":         len(b.Projects),
		"reports":          len(b.Reports),
		"connection_notes": len(b.ConnectionNotes),
	}
}
