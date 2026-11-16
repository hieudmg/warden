package clienthttp

import (
	"net/http"
	"strings"
	"testing"
)

func TestClientCapabilityAllowlist(t *testing.T) {
	for _, route := range []string{"GET ssh-connections", "GET ssh-connections/1", "GET ssh-connections/1/dependents", "PUT ssh-connections/1/archive", "GET db-connections", "GET db-connections/1", "GET db-connections/1/dependents", "PUT db-connections/1/archive", "GET transport/ssh/1", "GET transport/db/1?database=fixture", "GET projects", "POST projects", "GET projects/fixture/reports", "POST reports"} {
		method, path, _ := strings.Cut(route, " ")
		if !Allowed(method, "/api/v1/client/"+path) {
			t.Error("existing CLI capability omitted", route)
		}
	}
	for _, route := range []string{"GET /api/v1/ssh-connections", "GET /api/v1/client/groups", "GET /api/v1/client/key-pairs/1", "GET /api/v1/client/data/export", "POST /api/v1/client/auth/unlock", "POST /api/v1/client/ssh-connections", "DELETE /api/v1/client/db-connections/1", "GET https://attacker.invalid/api/v1/client/projects", "GET //attacker.invalid/api/v1/client/projects", "GET /api/v1/client/../key-pairs/1", "GET /api/v1/client/projects/", "GET /api/v1/client/transport/ssh/1?database=x", "GET /api/v1/client/transport/db/1?database=x&token=y"} {
		method, path, _ := strings.Cut(route, " ")
		if Allowed(method, path) {
			t.Error("unapproved capability allowed", route)
		}
	}
	hc := &http.Client{}
	own := Client(hc, 0)
	if own == hc || own.CheckRedirect == nil || hc.CheckRedirect != nil {
		t.Fatal("injected client was unguarded or mutated")
	}
}
