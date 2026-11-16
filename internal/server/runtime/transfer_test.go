package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
	"warden/internal/model"
	"warden/internal/server/audit"
	"warden/internal/server/profiles"
)

func mountProfiles(p *Plane) {
	mux := http.NewServeMux()
	profiles.New(p.store, audit.New(p.store)).Register(mux)
	p.managed = mux
}
func TestFreshVaultCRUDAndVersionOneExportImportIntoInitializedEmptyVault(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	mountProfiles(p)
	body := `{"name":"synthetic-key","private_key":"synthetic-private-key"}`
	g := requestGrant(t, p, signer, browser, csrf, "key_mutation", "POST", "/api/v1/key-pairs", body)
	create := callGranted(p, "POST", "/api/v1/key-pairs", body, browser, csrf, g)
	if create.Code != 201 || bytes.Contains(create.Body.Bytes(), []byte("synthetic-private-key")) {
		t.Fatal(create.Code, create.Body)
	}
	g = requestGrant(t, p, signer, browser, csrf, "key_reveal", "GET", "/api/v1/key-pairs/1", "")
	reveal := callGranted(p, "GET", "/api/v1/key-pairs/1", "", browser, csrf, g)
	if reveal.Code != 200 || !bytes.Contains(reveal.Body.Bytes(), []byte("synthetic-private-key")) {
		t.Fatal(reveal.Code, reveal.Body)
	}
	g = requestGrant(t, p, signer, browser, csrf, "export", "GET", "/api/v1/data/export", "")
	exported := callGranted(p, "GET", "/api/v1/data/export", "", browser, csrf, g)
	if exported.Code != 200 {
		t.Fatal(exported.Code, exported.Body)
	}
	var bundle model.DataBundle
	if err := json.Unmarshal(exported.Body.Bytes(), &bundle); err != nil || bundle.Format != "warden-data" || bundle.Version != 1 || len(bundle.KeyPairs) != 1 {
		t.Fatal("not documented v1", err)
	}
	for _, field := range []string{"passkey_wrapper", "recovery_wrapper", "authorization_generation", "csrf_hash", "web_sessions"} {
		if bytes.Contains(exported.Body.Bytes(), []byte(field)) {
			t.Fatal("auth data exported", field)
		}
	}
	dest, _, _, destKey, destSigner := runtimeFixture(t)
	destBrowser, destCSRF := sessionFor(t, dest)
	dest.vault.Unlock(destKey, dest.vault.Generation())
	mountProfiles(dest)
	before, _ := dest.store.Installation(context.Background())
	payload := exported.Body.String()
	g = requestGrant(t, dest, destSigner, destBrowser, destCSRF, "import", "POST", "/api/v1/data/import", payload)
	imported := callGranted(dest, "POST", "/api/v1/data/import", payload, destBrowser, destCSRF, g)
	if imported.Code != 204 {
		t.Fatal(imported.Code, imported.Body)
	}
	after, _ := dest.store.Installation(context.Background())
	if !bytes.Equal(before, after) {
		t.Fatal("import replaced initialized auth")
	}
	pair, err := dest.store.GetKeyPair(context.Background(), 1)
	if err != nil || string(pair.PrivateKey) != "synthetic-private-key" {
		t.Fatal(err)
	}
	g = requestGrant(t, dest, destSigner, destBrowser, destCSRF, "import", "POST", "/api/v1/data/import", payload)
	if result := callGranted(dest, "POST", "/api/v1/data/import", payload, destBrowser, destCSRF, g); result.Code != 409 {
		t.Fatal("nonempty import accepted", result.Code, result.Body)
	}
	g = requestGrant(t, p, signer, browser, csrf, "key_mutation", "DELETE", "/api/v1/key-pairs/1", "")
	if result := callGranted(p, "DELETE", "/api/v1/key-pairs/1", "", browser, csrf, g); result.Code != 204 {
		t.Fatal(result.Code, result.Body)
	}
}
func TestFreshImportBodyLimitFiftyMiB(t *testing.T) {
	p, _, _, key, signer := runtimeFixture(t)
	browser, csrf := sessionFor(t, p)
	p.vault.Unlock(key, p.vault.Generation())
	mountProfiles(p)
	bundle := model.DataBundle{Format: "warden-data", Version: 1, ExportedAt: time.Now().UTC(), Groups: []model.TransferGroup{{ID: 7, Name: "synthetic", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}}, KeyPairs: []model.TransferKeyPair{}, SSHConnections: []model.TransferSSHConnection{}, DBConnections: []model.TransferDBConnection{}, Projects: []model.TransferProject{}, Reports: []model.TransferReport{}, ConnectionNotes: []model.TransferConnectionNote{}}
	raw, _ := json.Marshal(bundle)
	body := string(raw) + strings.Repeat(" ", (50<<20)-len(raw))
	oversized := body + " "
	g := requestGrant(t, p, signer, browser, csrf, "import", "POST", "/api/v1/data/import", oversized)
	if result := callGranted(p, "POST", "/api/v1/data/import", oversized, browser, csrf, g); result.Code != 400 {
		t.Fatal("oversize accepted", result.Code)
	}
	if groups, err := p.store.ListGroups(context.Background()); err != nil || len(groups) != 0 {
		t.Fatal("oversize mutated dataset", err)
	}
	g = requestGrant(t, p, signer, browser, csrf, "import", "POST", "/api/v1/data/import", body)
	if result := callGranted(p, "POST", "/api/v1/data/import", body, browser, csrf, g); result.Code != 204 {
		t.Fatal("documented limit rejected", result.Code, result.Body)
	}
}
