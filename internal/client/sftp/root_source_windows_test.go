//go:build windows

package sftp

import "testing"

// This must execute on Windows for native path evidence. Root I/O remains
// entirely fake; no drive/UNC root is statted, listed, opened or modified.
func TestWindowsCopyRootSourceSpellingContentsTarget(t *testing.T) {
	paths := NewLocalFilesystem()
	for _, tc := range windowsRootSpellings {
		t.Run(tc.name, func(t *testing.T) {
			comparison, err := paths.Clean(tc.operand)
			if err != nil {
				t.Fatal(err)
			}
			if paths.Dir(comparison) != comparison {
				t.Fatalf("fixture is not a native root: operand=%q comparison=%q parent=%q", tc.operand, comparison, paths.Dir(comparison))
			}
			checkCopyRootSourceContentsTarget(t, paths, tc.operand)
		})
	}
}
