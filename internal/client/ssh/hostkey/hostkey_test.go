package hostkey

import (
	"strings"
	"testing"
)

func TestRemovalGuidance(t *testing.T) {
	t.Parallel()

	const path = "/tmp/known hosts"
	const host = "[oracle.example]:2222"

	posix := removalGuidance("linux", path, host)
	if !strings.Contains(posix, "ssh-keygen -f '/tmp/known hosts' -R '[oracle.example]:2222'") {
		t.Errorf("POSIX guidance = %q, want quoted ssh-keygen command", posix)
	}

	windows := removalGuidance("windows", path, host)
	if strings.Contains(windows, "ssh-keygen") || !strings.Contains(windows, path) {
		t.Errorf("Windows guidance = %q, want manual known_hosts removal guidance", windows)
	}
}
