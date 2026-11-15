package terminal

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxErrorBytes bounds the encoded diagnostic text, excluding the CLI's fixed
// command prefix and final newline. It is independent of IPC/HTTP body limits.
const MaxErrorBytes = 1024

// ErrorText formats only a diagnostic, never an SSH or file byte stream.
// Classification stays with the original error; callers must classify first.
func ErrorText(err error) string {
	if err == nil {
		return ""
	}
	return EscapeErrorText(err.Error())
}

// EscapeErrorText preserves printable Unicode and visibly escapes terminal
// controls/nonprintables and malformed UTF-8. Truncation emits only whole UTF-8
// runes or escape tokens; the 1024-byte cap includes escape expansion. Existing
// printable backslashes are not re-escaped, so already-safe API errors keep
// their meaning when rendered at the CLI boundary.
func EscapeErrorText(text string) string {
	var b strings.Builder
	for len(text) > 0 {
		r, n := utf8.DecodeRuneInString(text)
		var token string
		switch {
		case r == utf8.RuneError && n == 1:
			token = `\ufffd`
		case r == '\x1b':
			token = `\x1b`
		case r == '\r':
			token = `\r`
		case r == '\n':
			token = `\n`
		case r == '\t':
			token = `\t`
		case !unicode.IsPrint(r):
			if r <= 0xffff {
				token = fmt.Sprintf(`\u%04x`, r)
			} else {
				token = fmt.Sprintf(`\U%08x`, r)
			}
		default:
			token = text[:n]
		}
		if b.Len()+len(token) > MaxErrorBytes {
			break
		}
		b.WriteString(token)
		text = text[n:]
	}
	return b.String()
}
