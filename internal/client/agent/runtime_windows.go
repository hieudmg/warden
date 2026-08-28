//go:build windows

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/Microsoft/go-winio"
)

func runtimeEndpointPath(dir string) string {
	digest := sha256.Sum256([]byte(dir))
	return `\\.\pipe\warden-agent-` + hex.EncodeToString(digest[:])
}

func listenRuntime(_ *Runtime, path string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;OW)"})
}

func dialRuntime(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}

func cleanupRuntimeEndpoint(_ string) error {
	return nil
}

func ensurePrivateDirectory(path string) error {
	if path == "" {
		return errors.New("agent runtime directory is empty")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("create agent runtime directory: %w", err)
	}
	return nil
}

func validateTokenFileInfo(_ os.FileInfo) error {
	return nil
}
