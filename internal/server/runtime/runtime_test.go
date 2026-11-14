package runtime

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"testing/fstest"

	"warden/internal/config"
	"warden/internal/store"
)

func TestNormalRuntimeRefusesInvalidBeforeListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, cfg := range []config.Setup{{}, {PublicOrigin: "http://warden.example", RPID: "warden.example", Mode: "proxy"}} {
		if err := Run(ctx, Options{Config: cfg, Bind: "127.0.0.1:8080", DBPath: filepath.Join(t.TempDir(), "missing.db"), Assets: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("UI")}}}); err == nil {
			t.Fatal("invalid config started")
		}
	}
	var _ fs.FS = fstest.MapFS{}
}
func TestNormalRuntimeRejectsWrongRPWithoutMutation(t *testing.T) {
	p, _, _, _, _ := runtimeFixture(t)
	raw, err := p.store.Installation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mismatch.db")
	if err = store.CommitInstallation(context.Background(), path, raw); err != nil {
		t.Fatal(err)
	}
	cfg := p.cfg
	cfg.RPID = "example" // invalid public suffix must fail even before open
	err = Run(context.Background(), Options{Config: cfg, Bind: "127.0.0.1:8080", DBPath: path, Assets: fstest.MapFS{}})
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("RP mismatch", err)
	}
	after, err := store.ReadInstallation(context.Background(), path)
	if err != nil || string(after) != string(raw) {
		t.Fatal("identity changed", err)
	}
}
