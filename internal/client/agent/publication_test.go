package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRuntimePublicationUnlinkFailureIsNotReady(t *testing.T) {
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "a"))
	client, _ := NewRuntimeAt(runtime.dir)
	originalRemove := removeCredentialStage
	entered := make(chan string, 1)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	removals := 0
	removeCredentialStage = func(directory *privateDirectory, name string) error {
		removals++
		entered <- name
		<-release
		return os.ErrPermission
	}
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() { _, err := runtime.Listen(); result <- err; close(finished) }()
	t.Cleanup(func() {
		unblock()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("failed publication did not finish")
		}
		runtime.Cleanup()
		removeCredentialStage = originalRemove
	})
	var stage string
	select {
	case stage = <-entered:
	case <-time.After(time.Second):
		t.Fatal("publication did not reach staging removal")
	}
	// The real exclusive link already exists, but the two-link state is NOT
	// readiness: even an attaching client must reject it without a token.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, token, err := client.connect(ctx)
	if conn != nil {
		conn.Close()
	}
	if err == nil || len(token) != 0 {
		t.Fatal("client consumed incomplete publication")
	}
	before, err := os.ReadFile(client.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("unlink failure left startup blocked")
	}
	if err := <-result; !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Listen error = %v; want injected unlink failure", err)
	}
	if removals != 1 {
		t.Fatalf("retried ambiguous staging removal %d times", removals)
	}
	if err := runtime.Cleanup(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{runtimeToken, stage} {
		after, err := os.ReadFile(filepath.Join(runtime.dir, name))
		if err != nil || !bytes.Equal(after, before) {
			t.Fatal("failed startup changed ambiguous publication", name, err)
		}
	}
	if _, err := client.ReadToken(); err == nil {
		t.Fatal("consumed multiply-linked credentials after failed startup")
	}
	// Failed Listen must have released the native lock and listener, without
	// acquiring cleanup rights over the ambiguous credential names.
	directory, err := openPrivateDirectory(runtime.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	lock, err := openPrivateChild(directory.file, runtimeLock, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := lockRuntime(lock); err != nil {
		t.Fatal("failed startup retained runtime lock", err)
	}
	dialCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	if conn, err := dialRuntime(dialCtx, client.EndpointPath()); err == nil {
		conn.Close()
		t.Fatal("failed startup retained listener")
	}
}

func TestRuntimeInterruptedPublicationFailsClosed(t *testing.T) {
	runtime, _ := NewRuntimeAt(filepath.Join(t.TempDir(), "a"))
	if _, err := runtime.Listen(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(runtime.tokenPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Cleanup(); err != nil {
		t.Fatal(err)
	}
	directory, err := openPrivateDirectory(runtime.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	stage := ".credentials-interrupted"
	file, err := openPrivateChild(directory.file, stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		directory.Close()
		t.Fatal(err)
	}
	if err := writeAll(file, original); err != nil {
		file.Close()
		directory.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		directory.Close()
		t.Fatal(err)
	}
	file.Close()
	// A pre-publication crash leaves only an untrusted staging name; it cannot
	// be interpreted as readiness or as a pin by a reader.
	if _, err := runtime.ReadToken(); !errors.Is(err, os.ErrNotExist) {
		directory.Close()
		t.Fatal("read unpublished credentials", err)
	}
	// Simulate crash AFTER exclusive link publication but BEFORE staging unlink.
	// Multiple-link state is deliberately inconclusive, not automatically fixed.
	if err := directory.root.Link(stage, runtimeToken); err != nil {
		directory.Close()
		t.Fatal(err)
	}
	directory.Close()
	if _, err := runtime.ReadToken(); err == nil {
		t.Fatal("accepted interrupted multiply-linked discovery")
	}
	if _, err := runtime.Listen(); err == nil {
		runtime.Cleanup()
		t.Fatal("silently replaced inconclusive publication")
	}
	after, err := os.ReadFile(runtime.tokenPath())
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("changed inconclusive crash state", err)
	}
}
