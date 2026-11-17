package runtime

import (
	"strings"
	"testing"
)

func TestAccountAuditRoutesAreServerOwned(t *testing.T) {
	for _, route := range []string{"login", "unlock", "fresh", "reset"} {
		path := "/api/v1/auth/account/" + route
		want := "auth.account." + route
		if got := securityAuditOperation("POST", path); got != want {
			t.Fatalf("%s: %q", path, got)
		}
	}
	if got := securityAuditOperation("POST", "/api/v1/auth/account/"+strings.Repeat("sensitive", 10)); got != "" {
		t.Fatal("raw route admitted")
	}
}
