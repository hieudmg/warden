package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const certutilFixtureCleanupSnapshotEnv = "WARDEN_TEST_CLEANUP_SNAPSHOT"

type certutilFixtureCleanupTarget struct {
	Process certutilFixtureControlTarget
	Phase   string
}

func (target certutilFixtureCleanupTarget) validate() error {
	if target.Phase != "matrix" && target.Phase != "independent-cleanup" {
		return errors.New("unknown cleanup phase")
	}
	return target.Process.validate()
}

func certutilFixtureCleanupSnapshotCommand(ctx context.Context, target certutilFixtureCleanupTarget, env []string) (*exec.Cmd, error) {
	if err := target.validate(); err != nil {
		return nil, err
	}
	for _, value := range env {
		key, _, _ := strings.Cut(value, "=")
		if strings.EqualFold(key, certutilFixtureControlEnv) || strings.EqualFold(key, certutilFixtureSnapshotPID) || strings.EqualFold(key, certutilFixtureCleanupSnapshotEnv) {
			return nil, errors.New("inherited owned-process target refused")
		}
	}
	value, err := json.Marshal(target)
	if err != nil || len(value) > 4096 {
		return nil, errors.New("invalid/oversized public cleanup identity")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestCertutilFixtureOwnedCleanupSnapshotProcess$", "-test.v")
	cmd.Env = append(slices.Clone(env), certutilFixtureCleanupSnapshotEnv+"="+string(value))
	return cmd, nil
}

func (target certutilFixtureCleanupTarget) matchesProcess(creation uint64, queryErr error) bool {
	return queryErr == nil && creation == target.Process.Creation && target.validate() == nil
}

func certutilFixtureCleanupPublicControlEvidence(target certutilFixtureCleanupTarget, root uintptr, tid uint32, control certutilFixtureControl) string {
	if target.validate() != nil || root == 0 || tid == 0 || !control.Complete || control.HWND == 0 || control.Parent != uint64(root) || control.PID != uint32(target.Process.PID) || control.TID != tid || (control.Class != "Static" && control.Class != "Button") {
		return "cleanup owned control UNKNOWN: incomplete/raced/foreign metadata; text not emitted; NO ACTION"
	}
	return fmt.Sprintf("cleanup owned control hwnd=%d parent=%d pid=%d tid=%d id=%d class=%s %s", control.HWND, control.Parent, control.PID, control.TID, control.ID, control.Class, certutilFixtureCleanupPublicTextEvidence(target.Process.CA, control.Text))
}

// Only expected public identity occurrences are emitted. Unknown control strings
// are never logged and substring counts are NOT UI identity or consent evidence.
func certutilFixtureCleanupPublicTextEvidence(ca certutilFixtureCAIdentity, text string) string {
	return fmt.Sprintf("textRunes=%d expectedCNSubstringCount=%d expectedSHA1SubstringCount=%d; text not emitted; UI identity/layout UNKNOWN; NO ACTION", len([]rune(text)), strings.Count(text, ca.CN), strings.Count(text, ca.Thumbprint)+strings.Count(text, certutilFixtureTestThumb(ca.Thumbprint)))
}

type certutilFixtureCleanupObserver func(context.Context) (*exec.Cmd, error)

func certutilFixtureCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	deadline, _ := parent.Deadline()
	return context.WithDeadline(parent, deadline.Add(-8*time.Second))
}

// This runner observes only; it cannot establish cleanup success or approve UI.
func runCertutilFixtureCleanupDiagnostic(parent context.Context, cmd *exec.Cmd, bind func(int) (certutilFixtureCleanupObserver, error), logLine func(string)) error {
	parentDeadline, ok := parent.Deadline()
	if !ok || parent.Err() != nil || cmd.Cancel == nil || bind == nil || logLine == nil {
		return errors.New("bounded owned cleanup command and identity binder required")
	}
	cmd.WaitDelay = time.Second
	var logMu sync.Mutex
	var removalStarted atomic.Bool
	log := func(s string) {
		if s == "CurrentUser unique-CA-remove:begin" || s == "cleanup exact-certificate remove:begin" {
			removalStarted.Store(true)
		}
		logMu.Lock()
		defer logMu.Unlock()
		logLine(s)
	}
	stdout, stderr := &fixtureLineWriter{logLine: log}, &fixtureLineWriter{logLine: log}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	bindingReady := make(chan struct{})
	var snapshot certutilFixtureCleanupObserver
	var bindingErr error
	originalCancel := cmd.Cancel
	var once sync.Once
	var cancelErr error
	cmd.Cancel = func() error {
		once.Do(func() {
			<-bindingReady // Start-time creation identity, before Wait releases handle.
			deadline := time.Now().Add(6 * time.Second)
			if limit := parentDeadline.Add(-2 * time.Second); limit.Before(deadline) {
				deadline = limit
			}
			ctx, cancel := context.WithDeadline(parent, deadline)
			defer cancel()
			log(fmt.Sprintf("owned cleanup snapshot:begin pid=%d; read-only NO ACTION", cmd.Process.Pid))
			err := bindingErr
			if err == nil && !removalStarted.Load() {
				err = errors.New("exact guarded Remove phase not observed; no UI query")
			}
			if err == nil && snapshot == nil {
				err = errors.New("owned cleanup binding unavailable")
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				probe, probeErr := snapshot(ctx)
				err = probeErr
				if err == nil && probe == nil {
					err = errors.New("owned cleanup snapshot unavailable")
				}
				if err == nil {
					probe.WaitDelay = time.Second
					err = runPowerShellFixtureCommand(probe, log)
				}
			}
			log(fmt.Sprintf("owned cleanup snapshot joined: error=%v context=%v; missing/partial data=UNKNOWN, not no-UI", err, ctx.Err()))
			cancelErr = originalCancel() // Never suppress/change the owned kill/result.
		})
		return cancelErr
	}
	if err := cmd.Start(); err != nil {
		close(bindingReady)
		stdout.flush()
		stderr.flush()
		return err
	}
	snapshot, bindingErr = bind(cmd.Process.Pid)
	close(bindingReady)
	if bindingErr != nil {
		log("owned cleanup creation binding unavailable: UNKNOWN; normal cleanup result still required")
	}
	err := cmd.Wait() // Joins watchCtx/Cancel, process, and both output-copy workers.
	stdout.flush()
	stderr.flush()
	return err
}

func TestCertutilFixtureCleanupSnapshotCommandAndGuard(t *testing.T) {
	ca := certutilFixtureControlTestCA(t)
	target := certutilFixtureCleanupTarget{Process: certutilFixtureControlTarget{PID: 1234, Creation: 5678, CA: ca}, Phase: "matrix"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	env := []string{"OWNED_FIXTURE=only"}
	cmd, err := certutilFixtureCleanupSnapshotCommand(ctx, target, env)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cmd.Args, []string{exe, "-test.run=^TestCertutilFixtureOwnedCleanupSnapshotProcess$", "-test.v"}) || cmd.Cancel == nil || len(env) != 1 || len(cmd.Env) != 2 {
		t.Fatal("not one private read-only child/cloned environment")
	}
	var decoded certutilFixtureCleanupTarget
	if json.Unmarshal([]byte(strings.TrimPrefix(cmd.Env[1], certutilFixtureCleanupSnapshotEnv+"=")), &decoded) != nil || decoded != target {
		t.Fatal("immutable phase/PID/creation/full public DER identity lost")
	}
	cmd.Env[0] = "changed"
	if env[0] != "OWNED_FIXTURE=only" {
		t.Fatal("environment aliases parent")
	}
	for _, name := range []string{"unknown phase", "empty phase", "self PID", "zero creation", "wrong CN", "wrong SHA1", "wrong DER", "inherited controls", "inherited snapshot", "inherited cleanup"} {
		t.Run(name, func(t *testing.T) {
			bad := target
			in := slices.Clone(env)
			switch name {
			case "unknown phase":
				bad.Phase = "import"
			case "empty phase":
				bad.Phase = ""
			case "self PID":
				bad.Process.PID = os.Getpid()
			case "zero creation":
				bad.Process.Creation = 0
			case "wrong CN":
				bad.Process.CA.CN += "0"
			case "wrong SHA1":
				bad.Process.CA.Thumbprint = strings.Repeat("0", 40)
			case "wrong DER":
				bad.Process.CA.DERSHA256[0] ^= 1
			case "inherited controls":
				in = append(in, strings.ToLower(certutilFixtureControlEnv)+"=foreign")
			case "inherited snapshot":
				in = append(in, strings.ToLower(certutilFixtureSnapshotPID)+"=foreign")
			case "inherited cleanup":
				in = append(in, strings.ToLower(certutilFixtureCleanupSnapshotEnv)+"=foreign")
			}
			if c, e := certutilFixtureCleanupSnapshotCommand(ctx, bad, in); e == nil || c != nil {
				t.Error("unknown/foreign identity or authority accepted")
			}
		})
	}
	if err := os.WriteFile(ca.File, []byte("changed public DER"), 0600); err != nil {
		t.Fatal(err)
	}
	if c, e := certutilFixtureCleanupSnapshotCommand(ctx, target, env); e == nil || c != nil {
		t.Fatal("changed immutable CA accepted")
	}
}

func TestCertutilFixtureCleanupIncompleteMetadataIsUnknown(t *testing.T) {
	ca := certutilFixtureControlTestCA(t)
	target := certutilFixtureCleanupTarget{Process: certutilFixtureControlTarget{PID: 1234, Creation: 5678, CA: ca}, Phase: "matrix"}
	good := certutilFixtureControl{HWND: 10, Parent: 20, PID: 1234, TID: 12, ID: 65535, Class: "Static", Text: ca.CN + " " + ca.Thumbprint, Complete: true}
	if line := certutilFixtureCleanupPublicControlEvidence(target, 20, 12, good); !strings.Contains(line, "expectedCNSubstringCount=1 expectedSHA1SubstringCount=1") {
		t.Fatalf("public evidence missing: %s", line)
	}
	for _, name := range []string{"incomplete", "zero handle", "foreign parent", "foreign PID", "foreign TID", "unknown class"} {
		t.Run(name, func(t *testing.T) {
			control := good
			switch name {
			case "incomplete":
				control.Complete = false
			case "zero handle":
				control.HWND = 0
			case "foreign parent":
				control.Parent++
			case "foreign PID":
				control.PID++
			case "foreign TID":
				control.TID++
			case "unknown class":
				control.Class = "unknown-private-class"
			}
			line := certutilFixtureCleanupPublicControlEvidence(target, 20, 12, control)
			if !strings.Contains(line, "UNKNOWN") || strings.Contains(line, "SubstringCount") || strings.Contains(line, control.Text) || strings.Contains(line, "unknown-private-class") {
				t.Errorf("incomplete/foreign metadata promoted: %s", line)
			}
		})
	}
	if !target.matchesProcess(5678, nil) || target.matchesProcess(5679, nil) || target.matchesProcess(5678, errors.New("process completed/query failed")) {
		t.Error("pinned process liveness/creation guard failed")
	}
	bad := target
	bad.Process.CA.CN += "0"
	if bad.matchesProcess(5678, nil) {
		t.Error("public DER mismatch accepted as live target")
	}
}

func TestCertutilFixtureCleanupPublicTextNeverLeaksUnknown(t *testing.T) {
	ca := certutilFixtureControlTestCA(t)
	for _, text := range []string{"foreign secret ENV=never-log", "unknown warning " + ca.CN + " private=never-log " + certutilFixtureTestThumb(ca.Thumbprint)} {
		line := certutilFixtureCleanupPublicTextEvidence(ca, text)
		for _, unknown := range []string{"foreign", "secret", "ENV=", "never-log", "unknown warning", "private="} {
			if strings.Contains(line, unknown) {
				t.Fatalf("unknown text leaked: %q", line)
			}
		}
		if !strings.Contains(line, "UI identity/layout UNKNOWN; NO ACTION") {
			t.Error("counts promoted to approval")
		}
	}
}

// Supplemental source freeze, not a substitute for the real-process tests or
// native observation: R8 may not alter either Remove/absence program or import.
func TestCertutilFixtureCleanupDiagnosticNativeScope(t *testing.T) {
	source, err := os.ReadFile("installer_https_windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("`[^`]*`").FindAll(source, -1)
	want := []string{"8ff0e2f103287f301ac0561801ce61f827bc35a337dbb8522f04edffcc815bae", "78589535f8f9ccff1a21fe7c99e9dcb3074e789066253d2482ce306c711c8f69", "12ff2218134a408997816f0ffdebc6b33e2951a7e11ceae291df0104f35e202b"}
	if len(blocks) != len(want) {
		t.Fatal("PowerShell program count changed")
	}
	for i, b := range blocks {
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want[i] {
			t.Errorf("original exact guard/Remove/modes/absence program%d changed", i)
		}
	}
	reader, err := os.ReadFile("certutil_cleanup_diagnostic_windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"BM_CLICK", "0x00F5", "SendKeys", "SetForegroundWindow", "SetActiveWindow", "SetFocus", "PostMessage", "EnumWindows", "CertDeleteCertificate", "CertOpenStore", "runCertutilFixtureConsentImport", "certutilFixtureOwnedControls("} {
		if strings.Contains(string(reader), forbidden) {
			t.Errorf("read-only child includes forbidden seam %s", forbidden)
		}
	}
	if strings.Count(string(reader), "getText.Call(hwnd, 0x000D,") != 1 {
		t.Error("only one scoped read-only WM_GETTEXT message seam allowed")
	}
}

func TestCertutilFixtureCleanupDiagnosticBudgets(t *testing.T) {
	for _, budget := range []time.Duration{120 * time.Second, 20 * time.Second} {
		parent, stop := context.WithTimeout(context.Background(), budget)
		operation, cancel := certutilFixtureCleanupContext(parent)
		p, _ := parent.Deadline()
		d, _ := operation.Deadline()
		if !d.Equal(p.Add(-8 * time.Second)) {
			t.Errorf("reserve not inside %v", budget)
		}
		cancel()
		stop()
	}
	ctx, cancel := certutilFixtureCleanupContext(context.Background())
	defer cancel()
	if ctx.Err() == nil {
		t.Error("missing parent deadline must expire before Start")
	}
}

func TestCertutilFixtureCleanupDiagnosticLifecycle(t *testing.T) {
	const roleEnv = "WARDEN_TEST_CLEANUP_ROLE"
	const readyEnv = "WARDEN_TEST_CLEANUP_READY"
	switch os.Getenv(roleEnv) {
	case "cleanup":
		fmt.Println("cleanup exact-certificate remove:begin")
		time.Sleep(time.Minute)
		os.Exit(90)
	case "snapshot":
		fmt.Println("owned cleanup snapshot:NO ACTION")
		os.Exit(0)
	case "snapshot failure":
		os.Exit(7)
	case "snapshot hang":
		time.Sleep(time.Minute)
		os.Exit(91)
	case "normal":
		os.Exit(0)
	case "before removal":
		fmt.Println("actual-download:begin")
		time.Sleep(time.Minute)
		os.Exit(94)
	case "bind cancellation":
		fmt.Println("cleanup exact-certificate remove:begin")
		if err := os.WriteFile(os.Getenv(readyEnv), []byte("owned process started"), 0600); err != nil {
			os.Exit(92)
		}
		time.Sleep(time.Minute)
		os.Exit(93)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"matrix", "independent-cleanup"} {
		for _, scenario := range []string{"snapshot", "snapshot failure", "snapshot hang", "bind failure", "nil observer", "snapshot start failure", "normal", "parent cancelled", "start failure", "bind cancellation", "before removal"} {
			t.Run(phase+"/"+scenario, func(t *testing.T) {
				parent, cancelParent := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancelParent()
				operation, cancelOperation := certutilFixtureCleanupContext(parent)
				defer cancelOperation()
				cmd := exec.CommandContext(operation, exe, "-test.run=^TestCertutilFixtureCleanupDiagnosticLifecycle$")
				role := "cleanup"
				if scenario == "normal" {
					role = "normal"
				}
				if scenario == "bind cancellation" || scenario == "before removal" {
					role = scenario
				}
				ready := filepath.Join(t.TempDir(), "ready")
				cmd.Env = append(os.Environ(), roleEnv+"="+role, readyEnv+"="+ready, "GORACE=atexit_sleep_ms=0")
				if scenario == "start failure" {
					cmd.Path += ".missing"
				}
				var mu sync.Mutex
				var events []string
				add := func(s string) { mu.Lock(); defer mu.Unlock(); events = append(events, s) }
				kill := cmd.Cancel
				want := errors.New("owned original cancel result")
				kills := 0
				cmd.Cancel = func() error { kills++; add("kill-cleanup"); _ = kill(); return want }
				// Short controlled cancellation, never a larger fixture budget.
				watchDone := make(chan struct{})
				watch := time.AfterFunc(120*time.Millisecond, func() {
					defer close(watchDone)
					if scenario == "parent cancelled" {
						cancelParent()
					} else {
						cancelOperation()
					}
				})
				stopWatch := func() {
					if watch.Stop() {
						close(watchDone)
					}
					<-watchDone
				}
				defer stopWatch()
				var probe *exec.Cmd
				var cancelProbe context.CancelFunc = func() {}
				defer func() { cancelProbe() }()
				boundPID, observedPID := 0, 0
				err := runCertutilFixtureCleanupDiagnostic(parent, cmd, func(pid int) (certutilFixtureCleanupObserver, error) {
					add("bind")
					boundPID = pid
					if pid != cmd.Process.Pid || cmd.ProcessState != nil {
						t.Error("identity must bind after Start before Wait")
					}
					if scenario == "bind failure" {
						return nil, errors.New("identity unavailable")
					}
					if scenario == "bind cancellation" {
						deadline := time.Now().Add(time.Second)
						for time.Now().Before(deadline) {
							if _, e := os.Stat(ready); e == nil {
								break
							}
							time.Sleep(time.Millisecond)
						}
						cancelOperation() // Cancel must wait until immutable binding is published.
					}
					if scenario == "nil observer" {
						return nil, nil
					}
					return func(ctx context.Context) (*exec.Cmd, error) {
						add("snapshot-factory")
						observedPID = pid
						deadline, ok := ctx.Deadline()
						parentDeadline, _ := parent.Deadline()
						if !ok || deadline.After(parentDeadline.Add(-2*time.Second)) || time.Until(deadline) > 6*time.Second {
							t.Error("snapshot budget inflated")
						}
						if cmd.ProcessState != nil || kills != 0 {
							t.Error("snapshot target already waited/killed")
						}
						if scenario == "snapshot hang" {
							ctx, cancelProbe = context.WithTimeout(ctx, 80*time.Millisecond)
						}
						probe = exec.CommandContext(ctx, exe, "-test.run=^TestCertutilFixtureCleanupDiagnosticLifecycle$")
						probeRole := "snapshot"
						if scenario == "snapshot failure" || scenario == "snapshot hang" {
							probeRole = scenario
						}
						probe.Env = append(os.Environ(), roleEnv+"="+probeRole, "GORACE=atexit_sleep_ms=0")
						if scenario == "snapshot start failure" {
							probe.Path += ".missing"
						}
						return probe, nil
					}, nil
				}, add)
				stopWatch()
				if scenario == "start failure" {
					if err == nil || boundPID != 0 || probe != nil || kills != 0 {
						t.Error("failed Start acquired observer/target")
					}
					return
				}
				if cmd.ProcessState == nil || boundPID != cmd.Process.Pid {
					t.Error("owned cleanup process not bound/joined")
				}
				if scenario == "normal" {
					if err != nil || probe != nil || kills != 0 {
						t.Errorf("normal completion observed/killed: %v", err)
					}
					return
				}
				if err == nil || kills != 1 || !errors.Is(cmd.Cancel(), want) || kills != 1 {
					t.Errorf("cancel result/count changed: err=%v kills=%d", err, kills)
				}
				if probe != nil && probe.Process != nil && probe.ProcessState == nil {
					t.Error("snapshot not joined")
				}
				join := -1
				for i, e := range events {
					if strings.HasPrefix(e, "owned cleanup snapshot joined:") {
						join = i
					}
				}
				if join < 0 || slices.Index(events, "kill-cleanup") < join {
					t.Errorf("snapshot process/output must join before kill: %q", events)
				}
				if scenario == "before removal" && (observedPID != 0 || probe != nil) {
					t.Error("queried cleanup UI before exact guarded Remove phase")
				}
				if observedPID != 0 && observedPID != boundPID {
					t.Error("snapshot rebound to a different process")
				}
				if cmd.WaitDelay != time.Second || probe != nil && probe.WaitDelay != time.Second {
					t.Error("Wait/output bounds changed")
				}
			})
		}
	}
}
