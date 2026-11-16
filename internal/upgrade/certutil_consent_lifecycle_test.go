package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCertutilFixtureConsentImportLifecycle(t *testing.T) {
	const roleEnv = "WARDEN_TEST_CONSENT_ROLE"
	const markerEnv = "WARDEN_TEST_CONSENT_MARKER"
	const releaseEnv = "WARDEN_TEST_CONSENT_RELEASE"
	role := os.Getenv(roleEnv)
	waitFile := func(path string) {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		os.Exit(91)
	}
	switch role {
	case "wait-consent", "wait-consent-fail":
		waitFile(os.Getenv(markerEnv))
		if role == "wait-consent-fail" {
			os.Exit(7)
		}
		os.Exit(0)
	case "approve", "finalize":
		if err := os.WriteFile(os.Getenv(markerEnv), []byte("one fake owned dispatch"), 0600); err != nil {
			os.Exit(92)
		}
		if role == "finalize" {
			// Parent releases only AFTER actual import Wait/output join. This
			// forces the main-exit-before-observer-final-report interleaving.
			waitFile(os.Getenv(releaseEnv))
			fmt.Println("owned-consent:finalized after import wait")
		}
		os.Exit(0)
	case "normal":
		os.Exit(0)
	case "reject":
		os.Exit(3)
	case "completed":
		os.Exit(4) // no action; only normal import exit may reach DER postcondition
	case "hang":
		time.Sleep(time.Minute)
		os.Exit(93)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"consent normal", "finalize after normal wait", "normal no prompt", "normal but guard failure", "consent import failure", "guard failure", "observer unavailable", "observer start failure", "observer deadline", "cancel", "early import failure", "import start failure"} {
		t.Run(name, func(t *testing.T) {
			matrixCtx, cancelMatrix := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancelMatrix()
			importCtx, cancelImport := certutilFixtureImportContext(matrixCtx)
			defer cancelImport()
			marker := filepath.Join(t.TempDir(), "consent")
			release := marker + ".release"
			env := append(os.Environ(), markerEnv+"="+marker, releaseEnv+"="+release, "GORACE=atexit_sleep_ms=0")
			importRole, observerRole := "hang", "reject"
			switch name {
			case "consent normal":
				importRole, observerRole = "wait-consent", "approve"
			case "finalize after normal wait":
				importRole, observerRole = "wait-consent", "finalize"
			case "normal no prompt":
				importRole, observerRole = "normal", "completed"
			case "normal but guard failure":
				importRole = "normal"
			case "consent import failure":
				importRole, observerRole = "wait-consent-fail", "approve"
			case "observer deadline", "cancel":
				observerRole = "hang"
			case "early import failure":
				importRole = "reject"
			}
			cmd := exec.CommandContext(importCtx, exe, "-test.run=^TestCertutilFixtureConsentImportLifecycle$")
			cmd.Env = append(slices.Clone(env), roleEnv+"="+importRole)
			if name == "import start failure" {
				cmd.Path += ".missing"
			}
			var mu sync.Mutex
			var events []string
			var returned atomic.Bool
			var lateLogs atomic.Int32
			add := func(line string) {
				if returned.Load() {
					lateLogs.Add(1)
				}
				mu.Lock()
				defer mu.Unlock()
				events = append(events, line)
				if strings.HasPrefix(line, "owned certutil import joined:") && name == "finalize after normal wait" {
					if err := os.WriteFile(release, []byte("Wait completed"), 0600); err != nil {
						t.Error(err)
					}
				}
			}
			kills := 0
			originalCancel := cmd.Cancel
			cmd.Cancel = func() error { kills++; add("kill-import"); return originalCancel() }
			// Independent unchanged-size watchdog bounds broken implementations.
			watchdogDone := make(chan struct{})
			watchdog := time.AfterFunc(400*time.Millisecond, func() { defer close(watchdogDone); cancelImport() })
			stopWatchdog := func() {
				if watchdog.Stop() {
					close(watchdogDone)
				}
				<-watchdogDone
			}
			defer stopWatchdog()
			var observer *exec.Cmd
			var observerCancel context.CancelFunc = func() {}
			defer func() { observerCancel() }()
			err := runCertutilFixtureConsentImport(matrixCtx, cmd, func(ctx context.Context, pid int) (*exec.Cmd, error) {
				add("observer-factory")
				if pid != cmd.Process.Pid || importCtx.Err() != nil {
					t.Error("observer not proactive/owned")
				}
				deadline, ok := ctx.Deadline()
				matrixDeadline, _ := matrixCtx.Deadline()
				if !ok || deadline.After(matrixDeadline.Add(-2*time.Second)) || time.Until(deadline) > 6*time.Second {
					t.Error("observer budget inflated")
				}
				if name == "observer unavailable" {
					return nil, errors.New("unavailable")
				}
				if name == "observer deadline" {
					ctx, observerCancel = context.WithTimeout(ctx, 100*time.Millisecond)
				}
				observer = exec.CommandContext(ctx, exe, "-test.run=^TestCertutilFixtureConsentImportLifecycle$")
				observer.Env = append(slices.Clone(env), roleEnv+"="+observerRole)
				if name == "observer start failure" {
					observer.Path += ".missing"
				}
				return observer, nil
			}, add)
			stopWatchdog()
			returned.Store(true)
			ok := name == "consent normal" || name == "finalize after normal wait" || name == "normal no prompt"
			if (err == nil) != ok {
				t.Errorf("import result=%v wantSuccess=%v", err, ok)
			}
			if name == "import start failure" {
				if cmd.Process != nil || observer != nil || kills != 0 {
					t.Error("child started after failed import Start")
				}
				return
			}
			if cmd.ProcessState == nil || observer != nil && observer.Process != nil && observer.ProcessState == nil || matrixCtx.Err() != nil || lateLogs.Load() != 0 {
				t.Error("process/output/context not joined")
			}
			if cmd.WaitDelay != time.Second || observer != nil && observer.WaitDelay != time.Second {
				t.Error("WaitDelay changed")
			}
			join := -1
			for i, e := range events {
				if strings.HasPrefix(e, "owned controls observer joined:") {
					join = i
				}
			}
			if join < 0 {
				t.Errorf("observer join missing: %q", events)
			}
			if kill := slices.Index(events, "kill-import"); kill >= 0 && kill < join {
				t.Errorf("kill before observer/output join: %q", events)
			}
			wantKills := 1
			// A nonzero natural import exit is already joined; no redundant kill.
			if ok || name == "consent import failure" {
				wantKills = 0
			}
			if kills != wantKills {
				t.Errorf("original cancel calls=%d want=%d", kills, wantKills)
			}
			if name == "finalize after normal wait" && (observer.ProcessState == nil || !observer.ProcessState.Success() || !slices.Contains(events, "owned-consent:finalized after import wait")) {
				t.Errorf("normal exit cancelled finishing observer: %q", events)
			}
		})
	}
}
