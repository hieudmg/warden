package terminal

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEscapeErrorTextEncodedByteLimit(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"héllo 世界🙂", "héllo 世界🙂"},
		{"\x1b]52;c;x\a\r\n\t\x7f\u009b", `\x1b]52;c;x\u0007\r\n\t\u007f\u009b`},
		{"x\xffy", `x\ufffdy`},
		{strings.Repeat("x", 1023) + "界", strings.Repeat("x", 1023)},
		{strings.Repeat("界", 342), strings.Repeat("界", 341)},
		{strings.Repeat("x", 1021) + "\x1b", strings.Repeat("x", 1021)},
		{strings.Repeat("\x1b", 257), strings.Repeat(`\x1b`, 256)},
		{strings.Repeat("\u009b", 171), strings.Repeat(`\u009b`, 170)},
	} {
		got := EscapeErrorText(tc.input)
		if got != tc.want || len(got) > 1024 || !utf8.ValidString(got) {
			t.Fatalf("got %q (%d bytes), want %q", got, len(got), tc.want)
		}
		if EscapeErrorText(got) != got {
			t.Fatalf("safe text double escaped: %q", got)
		}
	}
	for r := rune(0); r <= 0x9f; r++ {
		if r >= 0x20 && r < 0x7f {
			continue
		}
		got := EscapeErrorText(string(r))
		if strings.ContainsRune(got, r) {
			t.Fatalf("raw control %U", r)
		}
	}
	sentinel := errors.New("sentinel\x1b")
	original := fmt.Errorf("relay: %w", sentinel)
	if ErrorText(original) != `relay: sentinel\x1b` || !errors.Is(original, sentinel) {
		t.Fatal("render changed original classification")
	}
	if ErrorText(nil) != "" {
		t.Fatal("nil diagnostic")
	}
}
