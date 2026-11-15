package ssh

import (
	"os"
	"runtime"
	"testing"
)

// Counts supplement the per-path connection/worker joins, not replace them.
// Cleanup runs after all parallel subtests and their fixture shutdowns.
func TestSSHFixtureRelayPathsJoinWithResourceSnapshots(t *testing.T) {
	beforeFDs, beforeGoroutines := fixtureResourceSnapshot(t)
	t.Cleanup(func() {
		afterFDs, afterGoroutines := fixtureResourceSnapshot(t)
		t.Logf("five relay paths: before fds=%d goroutines=%d; after joins/cleanup fds=%d goroutines=%d", beforeFDs, beforeGoroutines, afterFDs, afterGoroutines)
	})
	for _, test := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"graph", TestDialGraph},
		{"jump-command", TestRunCommandJumpChain},
		{"proxy-command", TestRunCommandThroughHTTPProxy},
		{"authenticated-proxy", TestRunCommandThroughProxyWithAuth},
		{"coalesced-proxy", TestRunCommandThroughHTTPProxyCoalescedBanner},
	} {
		t.Run(test.name, test.run)
	}
}

func fixtureResourceSnapshot(t *testing.T) (int, int) {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(fds), runtime.NumGoroutine()
}
