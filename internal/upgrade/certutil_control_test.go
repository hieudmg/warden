package upgrade

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1" // Disposable CA identity only, never payload verification.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const certutilFixtureControlEnv = "WARDEN_TEST_CERTUTIL_CONTROLS"

type certutilFixtureCAIdentity struct {
	File       string
	CN         string
	Thumbprint string
	DERSHA256  [32]byte
}

type certutilFixtureControlTarget struct {
	PID      int
	Creation uint64
	CA       certutilFixtureCAIdentity
}

func (target certutilFixtureControlTarget) validate() error {
	if target.PID <= 0 || uint64(target.PID) > 1<<32-1 || target.PID == os.Getpid() || target.Creation == 0 {
		return errors.New("missing/invalid owned process identity")
	}
	return target.CA.validateCertificate()
}

func (ca certutilFixtureCAIdentity) validateCertificate() error {
	if !filepath.IsAbs(ca.File) || len(ca.File) > 1024 || len(ca.CN) > 160 || !strings.HasPrefix(ca.CN, "Warden T16 isolated fixture ") || len(ca.Thumbprint) != 40 {
		return errors.New("missing/invalid generated CA identity")
	}
	f, err := os.Open(ca.File)
	if err != nil {
		return err
	}
	der, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(der) > 16<<10 || sha256.Sum256(der) != ca.DERSHA256 {
		return errors.New("public CA file DER changed")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	thumb := sha1.Sum(der)
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.Subject.CommonName != ca.CN || strings.ToUpper(hex.EncodeToString(thumb[:])) != ca.Thumbprint {
		return errors.New("public CA CN/full thumbprint mismatch")
	}
	return nil
}

func certutilFixtureControlCommand(ctx context.Context, target certutilFixtureControlTarget, env []string) (*exec.Cmd, error) {
	if err := target.validate(); err != nil {
		return nil, err
	}
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, certutilFixtureControlEnv) || strings.EqualFold(key, certutilFixtureSnapshotPID) {
			return nil, errors.New("refuse inherited observer target")
		}
	}
	value, err := json.Marshal(target)
	if err != nil {
		return nil, err
	}
	if len(value) > 4096 {
		return nil, errors.New("oversized public observer identity")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCertutilFixtureOwnedControlsProcess$", "-test.v")
	cmd.Env = append(slices.Clone(env), certutilFixtureControlEnv+"="+string(value))
	return cmd, nil
}

// No action contract is known yet. A live import is stopped after the single
// observer completes, even when its identity-only evidence matches. A naturally
// completed import still has to pass the fixture's exact-DER store postcondition.
func runCertutilFixtureControlObservation(matrixCtx context.Context, cmd *exec.Cmd, observer func(context.Context, int) (*exec.Cmd, error), logLine func(string)) error {
	matrixDeadline, ok := matrixCtx.Deadline()
	if !ok || matrixCtx.Err() != nil || cmd.Cancel == nil || observer == nil {
		return errors.New("bounded context-owned import and observer required")
	}
	deadline := time.Now().Add(6 * time.Second)
	if limit := matrixDeadline.Add(-2 * time.Second); limit.Before(deadline) {
		deadline = limit
	}
	obsCtx, cancelObserver := context.WithDeadline(matrixCtx, deadline)
	defer cancelObserver()
	if obsCtx.Err() != nil {
		return obsCtx.Err()
	}
	cmd.WaitDelay = time.Second
	observerDone := make(chan struct{})
	originalCancel := cmd.Cancel
	var cancelOnce sync.Once
	var cancelErr error
	cmd.Cancel = func() error {
		cancelOnce.Do(func() {
			cancelObserver()
			<-observerDone // observer process AND output joined before owned kill
			cancelErr = originalCancel()
		})
		return cancelErr
	}
	var logMu sync.Mutex
	log := func(line string) { logMu.Lock(); defer logMu.Unlock(); logLine(line) }
	stdout, stderr := &fixtureLineWriter{logLine: log}, &fixtureLineWriter{logLine: log}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		close(observerDone)
		stdout.flush()
		stderr.flush()
		return err
	}
	// Read Process only after Start, and construct the Windows creation-identity
	// envelope before launching Wait (which releases the owned process handle).
	probe, probeErr := observer(obsCtx, cmd.Process.Pid)
	mainDone := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		stdout.flush()
		stderr.flush()
		cancelObserver() // a normal/early exit must not leave an observer behind
		mainDone <- err
	}()
	if probeErr == nil && probe == nil {
		probeErr = errors.New("observer unavailable")
	}
	if probeErr == nil {
		probe.WaitDelay = time.Second
		probeErr = runPowerShellFixtureCommand(probe, log)
	}
	log(fmt.Sprintf("owned controls observer joined: error=%v context=%v; NO ACTION; native layout unverified", probeErr, obsCtx.Err()))
	close(observerDone)
	select {
	case err := <-mainDone:
		return err
	default:
		_ = cmd.Cancel()
		err := <-mainDone
		return fmt.Errorf("unverified consent contract; NO ACTION; observer=%v; import=%v", probeErr, err)
	}
}

type certutilFixtureControl struct {
	HWND, Parent uint64
	PID, TID     uint32
	ID           int32
	Class, Text  string
	Complete     bool
}

type certutilFixtureDialog struct {
	HWND           uint64
	PID, TID       uint32
	Creation       uint64
	Class, Caption string
	Complete       bool
	Controls       []certutilFixtureControl
}

// Identity evidence is NOT consent eligibility: labels/layout are unobserved.
func certutilFixtureControlIdentityEvidence(target certutilFixtureControlTarget, dialogs []certutilFixtureDialog) error {
	if err := target.validate(); err != nil {
		return err
	}
	if len(dialogs) != 1 {
		return errors.New("missing/ambiguous owned dialog")
	}
	d := dialogs[0]
	if !d.Complete || d.HWND == 0 || d.PID != uint32(target.PID) || d.TID == 0 || d.Creation != target.Creation || d.Class != "#32770" || d.Caption != "Security Warning" {
		return errors.New("unexpected/incomplete owned dialog identity")
	}
	cnCount, thumbCount := 0, 0
	seen := map[uint64]bool{}
	for _, c := range d.Controls {
		if !c.Complete || c.HWND == 0 || c.ID == 0 || seen[c.HWND] || c.Parent != d.HWND || c.PID != d.PID || c.TID != d.TID || c.Class != "Static" && c.Class != "Button" {
			return errors.New("unexpected/incomplete owned control identity")
		}
		seen[c.HWND] = true
		if c.Class != "Static" {
			continue
		}
		if c.Text == target.CA.CN {
			cnCount++
		}
		// Whole field only: do not extract a tempting substring from a label,
		// warning, abbreviated identity or otherwise unrecognized native layout.
		compact := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(c.Text)
		if len(compact) != 40 {
			continue
		}
		thumb, err := hex.DecodeString(compact)
		if err != nil {
			continue
		}
		if strings.ToUpper(hex.EncodeToString(thumb)) != target.CA.Thumbprint {
			return errors.New("conflicting full UI thumbprint")
		}
		thumbCount++
	}
	if cnCount != 1 || thumbCount != 1 {
		return errors.New("full standalone CN/thumbprint missing or duplicated; native layout UNKNOWN")
	}
	return nil // identity evidence only; NEVER authorizes or performs an action
}

func TestCertutilFixtureControlIdentityEvidence(t *testing.T) {
	ca := certutilFixtureControlTestCA(t)
	target := certutilFixtureControlTarget{PID: 1234, Creation: 5678, CA: ca}
	// Sanitized, synthetic whole-field Static/Button values following documented
	// WM_GETTEXT semantics. These IDs/text placements are NOT a native contract.
	good := certutilFixtureDialog{HWND: 10, PID: 1234, TID: 42, Creation: 5678, Class: "#32770", Caption: "Security Warning", Complete: true,
		Controls: []certutilFixtureControl{
			{HWND: 11, Parent: 10, PID: 1234, TID: 42, ID: 101, Class: "Static", Text: ca.CN, Complete: true},
			{HWND: 12, Parent: 10, PID: 1234, TID: 42, ID: 102, Class: "Static", Text: ca.Thumbprint, Complete: true},
		}}
	for _, name := range []string{"exact", "spaced full thumbprint", "no dialog", "duplicate dialog", "wrong PID", "wrong TID", "wrong process", "wrong parent", "wrong dialog class", "unexpected caption", "incomplete dialog", "incomplete control", "foreign control", "reused control", "missing control ID", "unexpected control class", "missing CN", "partial CN", "wrong CN", "missing thumbprint", "partial thumbprint", "malformed thumbprint", "wrong thumbprint", "conflicting thumbprint", "duplicate thumbprint", "duplicate CN"} {
		t.Run(name, func(t *testing.T) {
			d := good
			d.Controls = slices.Clone(good.Controls)
			dialogs := []certutilFixtureDialog{d}
			switch name {
			case "spaced full thumbprint":
				var parts []string
				for i := 0; i < 40; i += 2 {
					parts = append(parts, strings.ToLower(ca.Thumbprint[i:i+2]))
				}
				d.Controls[1].Text = strings.Join(parts, " ")
			case "no dialog":
				dialogs = nil
			case "duplicate dialog":
				dialogs = append(dialogs, d)
			case "wrong PID":
				d.PID++
			case "wrong TID":
				d.TID++
			case "wrong process":
				d.Creation++
			case "wrong parent":
				d.Controls[1].Parent++
			case "wrong dialog class":
				d.Class = "Other"
			case "unexpected caption":
				d.Caption = "Other"
			case "incomplete dialog":
				d.Complete = false
			case "incomplete control":
				d.Controls[1].Complete = false
			case "foreign control":
				d.Controls[1].PID++
			case "reused control":
				d.Controls[1].HWND = d.Controls[0].HWND
			case "missing control ID":
				d.Controls[1].ID = 0
			case "unexpected control class":
				d.Controls[1].Class = "Edit"
			case "missing CN":
				d.Controls[0].Text = ""
			case "partial CN":
				d.Controls[0].Text = ca.CN[:len(ca.CN)-1]
			case "wrong CN":
				d.Controls[0].Text += "0"
			case "missing thumbprint":
				d.Controls[1].Text = ""
			case "partial thumbprint":
				d.Controls[1].Text = ca.Thumbprint[:38]
			case "malformed thumbprint":
				d.Controls[1].Text = ca.Thumbprint[:38] + "ZZ"
			case "wrong thumbprint":
				d.Controls[1].Text = strings.Repeat("0", 40)
			case "conflicting thumbprint", "duplicate thumbprint", "duplicate CN":
				c := d.Controls[1]
				if name == "duplicate CN" {
					c = d.Controls[0]
				}
				c.HWND = 13
				if name == "conflicting thumbprint" {
					c.Text = strings.Repeat("0", 40)
				}
				d.Controls = append(d.Controls, c)
			}
			if len(dialogs) > 0 {
				dialogs[0] = d
			}
			err := certutilFixtureControlIdentityEvidence(target, dialogs)
			wantMatch := name == "exact" || name == "spaced full thumbprint"
			if (err == nil) != wantMatch {
				t.Errorf("identity-only match=%v want=%v error=%v", err == nil, wantMatch, err)
			}
		})
	}
}

func certutilFixtureControlTestCA(t *testing.T) certutilFixtureCAIdentity {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "Warden T16 isolated fixture 0123456789abcdef0123456789abcdef"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "public CA %&'[].der")
	if err := os.WriteFile(file, der, 0600); err != nil {
		t.Fatal(err)
	}
	thumb := sha1.Sum(der)
	return certutilFixtureCAIdentity{File: file, CN: ca.Subject.CommonName, Thumbprint: strings.ToUpper(hex.EncodeToString(thumb[:])), DERSHA256: sha256.Sum256(der)}
}

func TestCertutilFixtureControlCommandIdentityAndOwnership(t *testing.T) {
	ca := certutilFixtureControlTestCA(t)
	target := certutilFixtureControlTarget{PID: 1234, Creation: 5678, CA: ca}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	env := []string{"OWNED_FIXTURE=only"}
	cmd, err := certutilFixtureControlCommand(ctx, target, env)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cmd.Args, []string{exe, "-test.run=^TestCertutilFixtureOwnedControlsProcess$", "-test.v"}) || cmd.Cancel == nil {
		t.Errorf("not the context-owned control observer: %q", cmd.Args)
	}
	if len(env) != 1 || env[0] != "OWNED_FIXTURE=only" || len(cmd.Env) != 2 || cmd.Env[0] != env[0] {
		t.Fatalf("environment mutated or expanded: %q", cmd.Env)
	}
	cmd.Env[0] = "OWNED_FIXTURE=changed-copy"
	if env[0] != "OWNED_FIXTURE=only" {
		t.Fatal("observer environment aliases caller")
	}
	var decoded certutilFixtureControlTarget
	if !strings.HasPrefix(cmd.Env[1], certutilFixtureControlEnv+"=") || json.Unmarshal([]byte(strings.TrimPrefix(cmd.Env[1], certutilFixtureControlEnv+"=")), &decoded) != nil || decoded != target {
		t.Errorf("full immutable public CA/process identity absent: %q", cmd.Env[1])
	}
	for _, name := range []string{"zero PID", "self PID", "missing creation", "missing CN", "partial CN", "wrong CN", "missing thumbprint", "partial thumbprint", "wrong thumbprint", "wrong DER", "missing file", "inherited target"} {
		t.Run(name, func(t *testing.T) {
			bad := target
			inputEnv := slices.Clone(env)
			switch name {
			case "zero PID":
				bad.PID = 0
			case "self PID":
				bad.PID = os.Getpid()
			case "missing creation":
				bad.Creation = 0
			case "missing CN":
				bad.CA.CN = ""
			case "partial CN":
				bad.CA.CN = "Warden T16 isolated fixture"
			case "wrong CN":
				bad.CA.CN += "0"
			case "missing thumbprint":
				bad.CA.Thumbprint = ""
			case "partial thumbprint":
				bad.CA.Thumbprint = bad.CA.Thumbprint[:38]
			case "wrong thumbprint":
				bad.CA.Thumbprint = strings.Repeat("0", 40)
			case "wrong DER":
				bad.CA.DERSHA256[0] ^= 1
			case "missing file":
				bad.CA.File += ".missing"
			case "inherited target":
				inputEnv = append(inputEnv, certutilFixtureControlEnv+"=foreign")
			}
			if c, e := certutilFixtureControlCommand(ctx, bad, inputEnv); e == nil || c != nil {
				t.Errorf("unsafe observation accepted: %s", name)
			}
		})
	}
	// A changed public file cannot be substituted even with the same path.
	if err := os.WriteFile(ca.File, []byte("not the generated DER"), 0600); err != nil {
		t.Fatal(err)
	}
	if c, e := certutilFixtureControlCommand(ctx, target, env); e == nil || c != nil {
		t.Error("changed CA file accepted")
	}
}

func TestCertutilFixtureControlObservationLifecycle(t *testing.T) {
	const roleEnv = "WARDEN_TEST_CONTROL_ROLE"
	switch os.Getenv(roleEnv) {
	case "import", "block":
		fmt.Println("owned-child:ready")
		time.Sleep(time.Minute)
		os.Exit(0)
	case "normal":
		os.Exit(0)
	case "complete":
		fmt.Println("owned-controls:complete; NO ACTION")
		os.Exit(0)
	case "mismatch":
		fmt.Println("owned-controls:identity mismatch; NO ACTION")
		os.Exit(7)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"complete", "mismatch", "block", "unavailable", "nil observer", "start failure", "normal", "cancel", "early failure", "import start failure", "observer deadline"} {
		t.Run(scenario, func(t *testing.T) {
			matrixCtx, cancelMatrix := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancelMatrix()
			importCtx, cancelImport := certutilFixtureImportContext(matrixCtx)
			defer cancelImport()
			cmd := exec.CommandContext(importCtx, exe, "-test.run=^TestCertutilFixtureControlObservationLifecycle$")
			role := "import"
			if scenario == "normal" {
				role = "normal"
			}
			if scenario == "early failure" {
				role = "mismatch"
			}
			cmd.Env = append(os.Environ(), roleEnv+"="+role, "GORACE=atexit_sleep_ms=0")
			if scenario == "import start failure" {
				cmd.Path += ".missing"
			}
			var mu sync.Mutex
			var events []string
			add := func(event string) { mu.Lock(); defer mu.Unlock(); events = append(events, event) }
			originalCancel := cmd.Cancel
			cmd.Cancel = func() error { add("kill-import"); return originalCancel() }
			var observer *exec.Cmd
			observerCancel := func() {}
			defer func() { observerCancel() }()
			var observedPID int
			var factoryAfterCancel bool
			// This independent test watchdog terminates the old cancel-only baseline.
			watchdog := time.AfterFunc(400*time.Millisecond, cancelImport)
			defer watchdog.Stop()
			err := runCertutilFixtureControlObservation(matrixCtx, cmd, func(ctx context.Context, pid int) (*exec.Cmd, error) {
				add("observer-start")
				observedPID = pid
				factoryAfterCancel = importCtx.Err() != nil
				deadline, ok := ctx.Deadline()
				matrixDeadline, _ := matrixCtx.Deadline()
				if !ok || deadline.After(matrixDeadline.Add(-2*time.Second)) || time.Until(deadline) > 6*time.Second {
					t.Error("unbounded observer")
				}
				if scenario == "unavailable" {
					return nil, errors.New("observer unavailable")
				}
				if scenario == "nil observer" {
					return nil, nil
				}
				path := exe
				if scenario == "start failure" {
					path += ".missing"
				}
				if scenario == "observer deadline" {
					ctx, observerCancel = context.WithTimeout(ctx, 100*time.Millisecond)
				}
				observer = exec.CommandContext(ctx, path, "-test.run=^TestCertutilFixtureControlObservationLifecycle$")
				observerRole := scenario
				if scenario == "normal" || scenario == "cancel" || scenario == "early failure" || scenario == "observer deadline" {
					observerRole = "block"
				}
				observer.Env = append(os.Environ(), roleEnv+"="+observerRole, "GORACE=atexit_sleep_ms=0")
				return observer, nil
			}, add)
			watchdog.Stop()
			add("import-joined")
			if scenario == "import start failure" {
				if err == nil || cmd.Process != nil || observer != nil || observedPID != 0 {
					t.Fatal("observer invoked without a started import")
				}
				return
			}
			if cmd.ProcessState == nil || matrixCtx.Err() != nil || observedPID != cmd.Process.Pid || factoryAfterCancel {
				t.Errorf("observer must be proactive/owned and import joined: pid=%d state=%v late=%v matrix=%v", observedPID, cmd.ProcessState, factoryAfterCancel, matrixCtx.Err())
			}
			if scenario == "normal" {
				if err != nil {
					t.Errorf("normal import: %v", err)
				}
			} else if err == nil {
				t.Error("non-normal import accepted")
			}
			join := -1
			for i, e := range events {
				if strings.HasPrefix(e, "owned controls observer joined:") {
					join = i
				}
			}
			if join < 0 || join < slices.Index(events, "observer-start") || join > slices.Index(events, "import-joined") {
				t.Errorf("observer process/output not joined before return: %q", events)
			}
			if kill := slices.Index(events, "kill-import"); kill >= 0 && kill < join {
				t.Errorf("import kill preceded observer join: %q", events)
			}
			if observer != nil && observer.Process != nil && observer.ProcessState == nil {
				t.Error("observer not waited")
			}
			if cmd.WaitDelay != time.Second || observer != nil && observer.WaitDelay != time.Second {
				t.Error("join bounds changed")
			}
		})
	}
}

func TestCertutilFixtureControlObservationScopeAndCancelOwnership(t *testing.T) {
	source, err := os.ReadFile("certutil_control_windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{`windows.NewLazySystemDLL("user32.dll")`, "entry.OwnerProcessID == uint32(target.PID)", "creation == target.Creation", "root == 0", "attempt < 32", "entries > 4096", "threads > 32", "callbacks > 16", "len(d.Controls) == 32", "var text [1024]uint16", "getText.Call(hwnd, 0x000D,", "0x23, 100,", "currentParent != parent", "currentID != id", "currentClass != class", "os.Exit(3)", "target.validate()"} {
		if !strings.Contains(text, required) {
			t.Errorf("native observation guard absent: %s", required)
		}
	}
	for _, forbidden := range []string{`NewProc("EnumWindows")`, `NewProc("PostMessage`, "BM_CLICK", "SendKeys", "InvokePattern", "ReadProcessMemory", "SuspendThread", "PROCESS_ALL_ACCESS", "SMTO_NOTIMEOUTIFNOTHUNG"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("out-of-scope API/action: %s", forbidden)
		}
	}
	if strings.Count(text, "getText.Call(") != 1 || strings.Index(text, "if entry.OwnerProcessID == uint32(target.PID)") > strings.Index(text, "enumThread.Call(") {
		t.Error("only one literal WM_GETTEXT target read, after owner filtering, is authorized")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestCertutilFixtureControlObservationLifecycle$")
	cmd.Env = append(os.Environ(), "WARDEN_TEST_CONTROL_ROLE=import", "GORACE=atexit_sleep_ms=0")
	want := errors.New("original cancel sentinel")
	kill := cmd.Cancel
	var kills int
	cmd.Cancel = func() error { kills++; _ = kill(); return want }
	err = runCertutilFixtureControlObservation(ctx, cmd, func(probeCtx context.Context, pid int) (*exec.Cmd, error) {
		probe := exec.CommandContext(probeCtx, exe, "-test.run=^TestCertutilFixtureControlObservationLifecycle$")
		probe.Env = append(os.Environ(), "WARDEN_TEST_CONTROL_ROLE=complete", "GORACE=atexit_sleep_ms=0")
		return probe, nil
	}, func(string) {})
	if err == nil || cmd.ProcessState == nil || !errors.Is(cmd.Cancel(), want) || kills != 1 {
		t.Fatalf("original cancel result/exactly-once owned kill lost: process=%v kills=%d", err, kills)
	}
	unbounded := exec.CommandContext(context.Background(), exe)
	if err := runCertutilFixtureControlObservation(context.Background(), unbounded, nil, func(string) {}); err == nil || unbounded.Process != nil {
		t.Error("unbounded/missing observer started a process")
	}
}
