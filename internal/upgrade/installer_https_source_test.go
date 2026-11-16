package upgrade

import (
	"context"
	"os/exec"
	"slices"
	"testing"
)

// This fixed command is only for the unique, absent-before-import fixture CA.
// -f means Force overwrite, not a promise of noninteractive completion.
func certutilFixtureImportCommand(ctx context.Context, executable, caFile string) *exec.Cmd {
	return exec.CommandContext(ctx, executable, "-user", "-f", "-addstore", "Root", caFile)
}

func TestCertutilFixtureImportCommandArguments(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const executable = "C:/Windows/System32/certutil.exe"
	const caFile = `C:\private % & ' [fixture]\unique CA.der`
	cmd := certutilFixtureImportCommand(ctx, executable, caFile)
	want := []string{executable, "-user", "-f", "-addstore", "Root", caFile}
	if !slices.Equal(cmd.Args, want) || cmd.Path != executable {
		t.Fatalf("fixture import argv=%q path=%q, want exact current-user force-import argv=%q", cmd.Args, cmd.Path, want)
	}
	if cmd.Cancel == nil {
		t.Fatal("fixture import must remain owned by its cancellation context")
	}
}
