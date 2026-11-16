package upgrade

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// Only exception types/HRESULTs, never environment or certificate/key bytes.
// The inner fixture finally blocks still run before this outer failure report.
func powerShellFixtureProgram(program string) string {
	return `function Write-FixtureException($failure) {
    $cause = $failure.Exception
    for ($depth = 0; $null -ne $cause -and $depth -lt 4; $depth++) {
        [Console]::Out.WriteLine('Native HTTPS exception: '+$cause.GetType().FullName+'; HRESULT='+$cause.HResult)
        $cause = $cause.InnerException
    }
}
try {
` + program + `
} catch {
    Write-FixtureException $_
    throw
}
`
}

// The native fixture must retain its last phase even when its context kills
// PowerShell. Cmd.Run joins both the process and its output-copy goroutines.
func runPowerShellFixtureCommand(cmd *exec.Cmd, logLine func(string)) error {
	var logMu sync.Mutex
	log := func(line string) {
		logMu.Lock()
		defer logMu.Unlock()
		logLine(line)
	}
	stdout, stderr := &fixtureLineWriter{logLine: log}, &fixtureLineWriter{logLine: log}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	stdout.flush()
	stderr.flush()
	return err
}

// Bound partial lines (including PowerShell CLIXML) without buffering until
// process exit. Each stream has its own writer, so stderr cannot hide stdout
// phase labels behind an unterminated diagnostic line.
type fixtureLineWriter struct {
	logLine   func(string)
	pending   []byte
	truncated bool
}

const fixtureLineLimit = 1024

func (w *fixtureLineWriter) Write(data []byte) (int, error) {
	for _, b := range data {
		if b == '\n' {
			w.flush()
		} else if len(w.pending) < fixtureLineLimit {
			w.pending = append(w.pending, b)
		} else {
			w.truncated = true
		}
	}
	return len(data), nil
}

func (w *fixtureLineWriter) flush() {
	if len(w.pending) != 0 || w.truncated {
		line := string(bytes.TrimSuffix(w.pending, []byte{'\r'}))
		if w.truncated {
			line += " [truncated]"
		}
		w.logLine(line)
	}
	w.pending = w.pending[:0]
	w.truncated = false
}

func TestPowerShellFixtureOutputBoundsAndFragments(t *testing.T) {
	var lines []string
	w := &fixtureLineWriter{logLine: func(line string) { lines = append(lines, line) }}
	for _, fragment := range []string{"compile:", "begin\r\n", strings.Repeat("x", 4*fixtureLineLimit), "\n", "cleanup:end"} {
		if n, err := w.Write([]byte(fragment)); n != len(fragment) || err != nil {
			t.Fatalf("write: n=%d err=%v", n, err)
		}
		if len(w.pending) > fixtureLineLimit {
			t.Fatal("unbounded partial line")
		}
	}
	w.flush()
	if len(lines) != 3 || lines[0] != "compile:begin" || lines[1] != strings.Repeat("x", fixtureLineLimit)+" [truncated]" || lines[2] != "cleanup:end" {
		t.Fatalf("fragmented output: %#v", lines)
	}
}

func TestPowerShellFixtureCommandStreamsAndJoinsOnCancellation(t *testing.T) {
	const marker = "Native HTTPS phase: before-block"
	const childEnv = "WARDEN_TEST_PHASE_PROCESS"
	if os.Getenv(childEnv) == "1" {
		fmt.Fprintln(os.Stdout, marker)
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestPowerShellFixtureCommandStreamsAndJoinsOnCancellation$")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	seen := false
	err = runPowerShellFixtureCommand(cmd, func(line string) {
		if strings.Contains(line, marker) {
			seen = true
			if ctx.Err() != nil {
				t.Error("phase was buffered until after context cancellation")
			}
			cancel()
		}
	})
	if !seen || err == nil || ctx.Err() != context.Canceled {
		t.Fatalf("stream/cancel result: phase=%v process=%v context=%v", seen, err, ctx.Err())
	}
	if cmd.ProcessState == nil {
		t.Fatal("owned fixture process was not waited/joined")
	}
}
