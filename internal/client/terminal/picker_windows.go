package terminal

import (
	"io"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// PollPickerKey returns one Unicode key (or a native navigation key) and
// its repeat count. It shares port-watch's nonblocking one-record read,
// but doesn't drop Unicode or non-character navigation keys. The picker
// must be the only reader while polling, and stops at the confirming record.
func (s *windowsSession) PollPickerKey() (code rune, repeat int, err error) {
	const (
		keyEvent = 0x0001
		vkMenu   = 0x12
		vkEscape = 0x1b
		vkUp     = 0x26
		vkDown   = 0x28
	)
	in := windows.Handle(s.in.Fd())
	for range 32 { // Bound work even when the queue contains only ignored records.
		var record consoleInputRecord
		ok, err := winReadConsoleInputNowait(in, &record)
		if !ok || err != nil {
			return 0, 0, err
		}
		if record.eventType != keyEvent || (record.keyDown == 0 && record.virtualKey != vkMenu) {
			continue
		}
		code := rune(record.unicodeChar)
		if code == 0 {
			switch record.virtualKey {
			case vkUp:
				code = PickerKeyUp
			case vkDown:
				code = PickerKeyDown
			case vkEscape:
				code = PickerKeyEscape
			default:
				continue
			}
		} else if code == '\x1b' && record.virtualKey == vkEscape {
			// A native Escape is unambiguous. An ESC in VT data still goes
			// through the picker's byte decoder for split arrow sequences.
			code = PickerKeyEscape
		}
		if 0xd800 <= code && code <= 0xdbff {
			s.pickerHighSurrogate = code
			continue
		}
		high := s.pickerHighSurrogate
		s.pickerHighSurrogate = 0
		if 0xdc00 <= code && code <= 0xdfff {
			if high == 0 {
				continue
			}
			code = utf16.DecodeRune(high, code)
		}
		if code == 0x1a { // Match os.File's console EOF (Ctrl-Z).
			return 0, 0, io.EOF
		}
		return code, max(1, int(record.repeatCount)), nil
	}
	return 0, 0, nil
}
