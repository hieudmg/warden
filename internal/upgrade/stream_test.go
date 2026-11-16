package upgrade

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUpgradeStreamLimitsTimeoutChecksumAndRollback(t *testing.T) {
	const asset = "warden-linux-amd64"
	for _, scenario := range []string{"exact limit", "binary limit+1", "checksum exact limit", "checksum limit+1", "truncated binary", "truncated checksum", "bad digest", "slow body", "slow headers", "shared deadline", "redirect deadline", "replace failure", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			settings := defaultDownloadSettings
			settings.binaryBytes = 16
			settings.checksumBytes = 128
			settings.connect = 80 * time.Millisecond
			settings.total = 180 * time.Millisecond
			payload := strings.Repeat("b", 16)
			if scenario == "binary limit+1" {
				payload += "b"
			}
			sums := sha256Hex(payload) + "  ./" + asset + "\n"
			if scenario == "checksum exact limit" {
				settings.checksumBytes = int64(len(sums))
			}
			if scenario == "checksum limit+1" {
				settings.checksumBytes = int64(len(sums) - 1)
			}
			if scenario == "bad digest" {
				sums = sha256Hex("wrong") + "  " + asset + "\n"
			}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "redirect deadline" {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(110 * time.Millisecond):
					}
					http.Redirect(w, r, r.URL.Path+"/next", http.StatusTemporaryRedirect)
					return
				}
				isSum := r.URL.Path == "/SHA256SUMS"
				body := payload
				if isSum {
					body = sums
				}
				if scenario == "slow headers" {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(300 * time.Millisecond):
					}
				}
				if scenario == "shared deadline" {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(110 * time.Millisecond):
					}
				}
				if scenario == "truncated binary" && !isSum || scenario == "truncated checksum" && isSum {
					w.Header().Set("Content-Length", fmt.Sprint(len(body)+5))
					io.WriteString(w, body)
					return
				}
				w.WriteHeader(200)
				w.(http.Flusher).Flush() // chunked, no Content-Length
				if scenario == "slow body" || scenario == "cancel" {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(300 * time.Millisecond):
					}
				}
				io.WriteString(w, body)
			}))
			defer srv.Close()
			if scenario == "shared deadline" || scenario == "redirect deadline" {
				settings.connect = 200 * time.Millisecond
			}
			dir, exe := newExecutable(t, "warden", "old binary")
			names := []string{"warden"}
			for _, name := range []string{"server.json", "warden.db", "warden.db-wal", "warden.db-shm", "master.key", "warden-server.service"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("preserve "+name), 0600); err != nil {
					t.Fatal(err)
				}
				names = append(names, name)
			}
			ctx := context.Background()
			if scenario == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			replaced := 0
			start := time.Now()
			_, err := Upgrade(ctx, Client, Options{ReleaseBaseURL: srv.URL, HTTPClient: srv.Client(), GOOS: "linux", GOARCH: "amd64", ExecutablePath: exe, settings: &settings, Replace: func(p, e string, m fs.FileMode) (bool, error) {
				replaced++
				if mode := fileMode(t, p); runtime.GOOS != "windows" && mode != 0600 {
					t.Errorf("stage mode=%v", mode)
				}
				if scenario == "replace failure" {
					return false, fmt.Errorf("fixture rename failure")
				}
				return false, nil
			}})
			success := scenario == "exact limit" || scenario == "checksum exact limit"
			if success && err != nil {
				t.Fatal(err)
			}
			if !success && err == nil {
				t.Fatal("accepted failed transfer")
			}
			if !success && scenario != "replace failure" && replaced != 0 {
				t.Fatal("replacement before verification")
			}
			if time.Since(start) > time.Second {
				t.Fatal("operation exceeded bounded cleanup")
			}
			assertFileContent(t, exe, "old binary")
			for _, name := range names[1:] {
				assertFileContent(t, filepath.Join(dir, name), "preserve "+name)
				if runtime.GOOS != "windows" && fileMode(t, filepath.Join(dir, name)) != 0600 {
					t.Fatal("changed state permissions")
				}
			}
			assertDirEntries(t, dir, names...)
		})
	}
}
