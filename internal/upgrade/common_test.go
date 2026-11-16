package upgrade

import (
	"fmt"
	"strings"
)

// installerDownloaderSource is shared by the portable source regression and
// native tests that compile the actual installer C#, not an alternate fixture.
func installerDownloaderSource(script []byte) (string, error) {
	// Git's native Windows checkout may use CRLF; normalize only line endings
	// before matching the PowerShell here-string boundaries.
	normalized := strings.ReplaceAll(string(script), "\r\n", "\n")
	_, source, ok := strings.Cut(normalized, "-TypeDefinition @'\n")
	if !ok {
		return "", fmt.Errorf("missing embedded downloader")
	}
	source, rest, ok := strings.Cut(source, "\n'@")
	if !ok || rest != "" && !strings.HasPrefix(rest, "\n") || strings.TrimSpace(source) == "" {
		return "", fmt.Errorf("missing C# boundary")
	}
	return source, nil
}
