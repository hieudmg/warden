package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const certutilFixtureSnapshotPID = "WARDEN_TEST_CERTUTIL_SNAPSHOT_PID"

func certutilFixtureImportContext(matrixCtx context.Context) (context.Context, context.CancelFunc) {
	deadline, _ := matrixCtx.Deadline()
	// Missing deadline yields an already-expired context, never an unbounded child.
	return context.WithDeadline(matrixCtx, deadline.Add(-8*time.Second))
}

func attachCertutilFixtureDiagnostic(matrixCtx context.Context, cmd *exec.Cmd, snapshotCommand func(context.Context, int) (*exec.Cmd, error), logLine func(string)) {
	cmd.WaitDelay = time.Second
	originalCancel := cmd.Cancel
	cmd.Cancel = func() (cancelErr error) {
		// watchCtx calls Cancel only after Start has set Process. Always retain
		// the original kill/result, even when observation cannot start or fails.
		defer func() { cancelErr = originalCancel() }()
		matrixDeadline, _ := matrixCtx.Deadline()
		deadline := time.Now().Add(6 * time.Second)
		if limit := matrixDeadline.Add(-2 * time.Second); limit.Before(deadline) {
			deadline = limit
		}
		ctx, cancel := context.WithDeadline(matrixCtx, deadline)
		defer cancel()
		logLine(fmt.Sprintf("owned certutil snapshot:begin pid=%d; observation only", cmd.Process.Pid))
		snapshot, err := snapshotCommand(ctx, cmd.Process.Pid)
		if err == nil {
			snapshot.WaitDelay = time.Second
			err = runPowerShellFixtureCommand(snapshot, logLine)
		}
		logLine(fmt.Sprintf("owned certutil snapshot joined: error=%v context=%v; missing/partial metadata=UNKNOWN", err, ctx.Err()))
		return nil
	}
}

func certutilFixtureSnapshotCommand(ctx context.Context, pid int, env []string) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCertutilFixtureOwnedSnapshotProcess$", "-test.v")
	cmd.Env = append(slices.Clone(env), certutilFixtureSnapshotPID+"="+strconv.Itoa(pid))
	return cmd, nil
}

func TestCertutilFixtureSnapshotCommandAndScope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := []string{"OWNED_FIXTURE=only"}
	cmd, err := certutilFixtureSnapshotCommand(ctx, 1234, env)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cmd.Args, []string{executable, "-test.run=^TestCertutilFixtureOwnedSnapshotProcess$", "-test.v"}) || !slices.Equal(cmd.Env, []string{"OWNED_FIXTURE=only", certutilFixtureSnapshotPID + "=1234"}) || cmd.Cancel == nil || len(env) != 1 {
		t.Fatalf("snapshot must be one context-owned current test binary, exact child entry/PID, no shell or environment mutation: args=%q env=%q", cmd.Args, cmd.Env)
	}
	data, err := os.ReadFile("certutil_diagnostic_windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"func TestCertutilFixtureOwnedSnapshotProcess(", "pid == uint64(os.Getpid())", `windows.NewLazySystemDLL("user32.dll")`, "entry.OwnerProcessID == pid", "owner == pid && windowThread == tid", "var class [64]uint16", "var caption [128]uint16", "callbacks > 16", "threads == 32", "absent/unavailable/partial metadata=UNKNOWN"} {
		if !strings.Contains(source, required) {
			t.Fatalf("native-only source ownership/bounds guard absent: %s", required)
		}
	}
	if strings.Count(source, "if !ownsWindow(hwnd)") != 4 || strings.Index(source, "if entry.OwnerProcessID == pid") > strings.Index(source, "enumThreadWindows.Call") {
		t.Fatal("owned thread filter and repeated PID/thread checks must precede class/caption/presence observations")
	}
	for _, forbidden := range []string{`NewProc("EnumWindows")`, `NewProc("EnumChildWindows")`, `NewProc("SendMessage`, `NewProc("PostMessage`, "ReadProcessMemory", "SuspendThread", "GetWindowTextLength", "MainWindowTitle", "MainWindowHandle"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("unapproved or unreliable diagnostic API: %s", forbidden)
		}
	}
}

func TestCertutilFixtureImportDiagnosticBudget(t *testing.T) {
	matrixCtx, cancelMatrix := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelMatrix()
	importCtx, cancelImport := certutilFixtureImportContext(matrixCtx)
	defer cancelImport()
	matrixDeadline, _ := matrixCtx.Deadline()
	importDeadline, _ := importCtx.Deadline()
	if !importDeadline.Equal(matrixDeadline.Add(-8 * time.Second)) {
		t.Fatalf("import deadline must reserve 8s INSIDE 120s matrix: got=%v matrix=%v", importDeadline, matrixDeadline)
	}
	unbounded, cancel := certutilFixtureImportContext(context.Background())
	defer cancel()
	if unbounded.Err() == nil {
		t.Fatal("missing matrix deadline must fail closed before starting a child")
	}
}

func TestCertutilFixtureDiagnosticPreservesOriginalCancelResult(t *testing.T) {
	matrixCtx, cancelMatrix := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelMatrix()
	importCtx, cancelImport := certutilFixtureImportContext(matrixCtx)
	defer cancelImport()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := certutilFixtureImportCommand(importCtx, executable, "unused-owned-fixture.der")
	cmd.Args = []string{executable, "-test.run=^TestCertutilFixtureDiagnosticLifecycle$"}
	cmd.Env = append(os.Environ(), "WARDEN_TEST_CERTUTIL_DIAGNOSTIC_ROLE=import")
	want := errors.New("original cancel result")
	originalCancel := cmd.Cancel
	cmd.Cancel = func() error {
		if err := originalCancel(); err != nil {
			return err
		}
		return want
	}
	attachCertutilFixtureDiagnostic(matrixCtx, cmd, func(context.Context, int) (*exec.Cmd, error) {
		return nil, errors.New("observer failure must not replace original cancel result")
	}, func(string) {})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	cancelErr := cmd.Cancel() // synchronous, AFTER Start; only an owned child
	waitErr := cmd.Wait()
	if !errors.Is(cancelErr, want) || waitErr == nil || cmd.ProcessState == nil {
		t.Fatalf("original cancel result/join lost: cancel=%v wait=%v state=%v", cancelErr, waitErr, cmd.ProcessState)
	}
}

func TestCertutilFixtureDiagnosticLifecycle(t *testing.T) {
	const roleEnv = "WARDEN_TEST_CERTUTIL_DIAGNOSTIC_ROLE"
	switch os.Getenv(roleEnv) {
	case "import":
		fmt.Println("fake-import:ready")
		time.Sleep(time.Minute)
		os.Exit(0)
	case "normal":
		os.Exit(0)
	case "success":
		fmt.Println("fake-snapshot:complete")
		os.Exit(0)
	case "failure":
		fmt.Println("fake-snapshot:failed")
		os.Exit(7)
	case "block":
		fmt.Println("fake-snapshot:blocked")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"success", "failure", "block", "unavailable", "start-failure", "normal"} {
		t.Run(scenario, func(t *testing.T) {
			matrixCtx, cancelMatrix := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancelMatrix()
			importCtx, cancelImport := certutilFixtureImportContext(matrixCtx)
			defer cancelImport()
			cmd := certutilFixtureImportCommand(importCtx, executable, "unused-owned-fixture.der")
			// Replace only the external tool with an owned Go helper, not the
			// context/Cancel/diagnostic/streaming implementation under test.
			cmd.Args = []string{executable, "-test.run=^TestCertutilFixtureDiagnosticLifecycle$"}
			role := "import"
			if scenario == "normal" {
				role = "normal"
			}
			cmd.Env = append(os.Environ(), roleEnv+"="+role)
			var mu sync.Mutex
			var events []string
			add := func(event string) { mu.Lock(); defer mu.Unlock(); events = append(events, event) }
			originalCancel := cmd.Cancel
			cmd.Cancel = func() error { add("kill-import"); return originalCancel() }
			var snapshot *exec.Cmd
			var observedPID int
			var probeErrors []string
			attachCertutilFixtureDiagnostic(matrixCtx, cmd, func(ctx context.Context, pid int) (*exec.Cmd, error) {
				observedPID = pid // read only in Cancel, never concurrently with Start
				add("snapshot-start")
				deadline, ok := ctx.Deadline()
				matrixDeadline, _ := matrixCtx.Deadline()
				if !ok || deadline.After(matrixDeadline.Add(-2*time.Second)) || time.Until(deadline) > 6*time.Second || ctx.Err() != nil {
					probeErrors = append(probeErrors, "snapshot exceeds reserved deadline or inherits canceled import context")
				}
				if scenario == "unavailable" {
					return nil, errors.New("fixture observation unavailable")
				}
				path := executable
				if scenario == "start-failure" {
					path = executable + ".missing"
				}
				snapshot = exec.CommandContext(ctx, path, "-test.run=^TestCertutilFixtureDiagnosticLifecycle$")
				snapshot.Env = append(os.Environ(), roleEnv+"="+scenario)
				return snapshot, nil
			}, func(line string) { add(line) })
			processErr := runPowerShellFixtureCommand(cmd, func(line string) {
				if line == "fake-import:ready" {
					cancelImport()
				}
			})
			add("import-joined")
			// Run has joined watchCtx, Cancel and both output copiers, so every
			// observation below is after the last possible callback write.
			if cmd.ProcessState == nil || matrixCtx.Err() != nil {
				t.Fatalf("owned import did not join inside matrix: state=%v error=%v matrix=%v", cmd.ProcessState, processErr, matrixCtx.Err())
			}
			if scenario == "normal" {
				if processErr != nil || observedPID != 0 || !slices.Equal(events, []string{"import-joined"}) {
					t.Fatalf("successful import must not invoke observer/cancel: error=%v events=%q", processErr, events)
				}
				return
			}
			if processErr == nil || importCtx.Err() != context.Canceled || observedPID != cmd.Process.Pid || len(probeErrors) != 0 {
				t.Fatalf("cancel/ownership/budget: process=%v context=%v pid=%d errors=%q events=%q", processErr, importCtx.Err(), observedPID, probeErrors, events)
			}
			kill := slices.Index(events, "kill-import")
			joined := -1
			for i, event := range events {
				if strings.HasPrefix(event, "owned certutil snapshot joined:") {
					joined = i
				}
			}
			if joined <= slices.Index(events, "snapshot-start") || kill <= joined || slices.Index(events, "import-joined") <= kill {
				t.Fatalf("require snapshot completion/join, then original kill, then import join: %q", events)
			}
			if snapshot != nil && scenario != "start-failure" && snapshot.ProcessState == nil {
				t.Fatal("snapshot process/output was not waited/joined")
			}
			if snapshot != nil && snapshot.WaitDelay != time.Second || cmd.WaitDelay != time.Second {
				t.Fatal("each bounded join must retain the reserved 1s WaitDelay")
			}
			if scenario == "success" && (snapshot.ProcessState.ExitCode() != 0 || slices.Index(events, "fake-snapshot:complete") < 0 || slices.Index(events, "fake-snapshot:complete") >= joined) {
				t.Fatalf("successful snapshot output not joined before kill: %q", events)
			}
			if scenario == "failure" && snapshot.ProcessState.ExitCode() != 7 {
				t.Fatal("observer failure status lost")
			}
			if scenario == "block" && snapshot.ProcessState.Success() {
				t.Fatal("blocked observer was not canceled/killed and joined")
			}
		})
	}
}
