package picker

import (
	"errors"
	"io"
	"time"
	"unicode"
	"unicode/utf8"

	"warden/internal/client/terminal"
)

// Key classifies a decoded input event.
type Key uint8

const (
	// KeyRune is a printable character typed into the query.
	KeyRune Key = iota
	// KeyBackspace deletes the last query character.
	KeyBackspace
	// KeyUp and KeyDown move the selection (or the detail viewport when
	// it has focus).
	KeyUp
	KeyDown
	// KeyTab toggles focus between the list and the detail viewport.
	KeyTab
	// KeyEnter confirms the selected connection.
	KeyEnter
	// KeyCancel aborts the picker (Ctrl-C or bare ESC).
	KeyCancel
)

// DecodedKey is one input event produced from raw terminal bytes.
type DecodedKey struct {
	Kind Key
	Rune rune // valid when Kind is KeyRune
}

// StreamDecoder incrementally converts raw terminal bytes into decoded
// keys. Incomplete escape sequences and multi-byte runes are buffered until
// the full sequence arrives.
type StreamDecoder struct {
	pending []byte
}

// Feed decodes the newly arrived bytes plus any buffered prefix and returns
// the completed key events. A trailing lone ESC or ESC [ is retained until
// the following byte decides its meaning.
func (d *StreamDecoder) Feed(b []byte) []DecodedKey {
	d.pending = append(d.pending, b...)
	var out []DecodedKey
	for len(d.pending) > 0 {
		if d.pending[0] == 0x1b {
			if len(d.pending) == 1 {
				break // lone ESC: wait for the next byte
			}
			if d.pending[1] == '[' {
				if len(d.pending) < 3 {
					break // ESC [: wait for the final byte
				}
				switch d.pending[2] {
				case 'A':
					out = append(out, DecodedKey{Kind: KeyUp})
				case 'B':
					out = append(out, DecodedKey{Kind: KeyDown})
				}
				d.pending = d.pending[3:] // unknown ESC [ x is dropped
				continue
			}
			out = append(out, DecodedKey{Kind: KeyCancel})
			d.pending = d.pending[1:]
			continue
		}
		if !utf8.FullRune(d.pending) {
			break // truncated multi-byte rune: wait for more bytes
		}
		r, size := utf8.DecodeRune(d.pending)
		if r == utf8.RuneError && size == 1 {
			d.pending = d.pending[1:] // invalid byte is dropped
			continue
		}
		d.pending = d.pending[size:]
		if k, ok := keyForRune(r); ok {
			out = append(out, k)
		}
	}
	return out
}

// Pending returns the bytes currently buffered awaiting completion of an
// escape sequence or multi-byte rune.
func (d *StreamDecoder) Pending() []byte { return d.pending }

// Flush resolves whatever was buffered at the end of a stream: a lone ESC
// becomes KeyCancel; other incomplete sequences are dropped. It resets the
// decoder so a fresh input stream can follow.
func (d *StreamDecoder) Flush() []DecodedKey {
	var out []DecodedKey
	if len(d.pending) == 1 && d.pending[0] == 0x1b {
		out = append(out, DecodedKey{Kind: KeyCancel})
	}
	d.pending = nil
	return out
}

const escGrace = 50 * time.Millisecond

type pickerInput struct {
	session   terminal.Session
	decoder   StreamDecoder
	escapeDue time.Time
}

// poll consumes at most one input byte or one decoded console key. A lone
// ESC needs a bounded lookahead to distinguish it from a split arrow. No
// intermediate reader can hold bytes past the key that completes selection.
func (p *pickerInput) poll(now time.Time) (keys []DecodedKey, repeat int, progressed bool, err error) {
	if !p.escapeDue.IsZero() && !now.Before(p.escapeDue) {
		p.escapeDue = time.Time{}
		// An expired lone ESC completes cancellation. Leave any newly
		// queued bytes for the next terminal owner.
		if keys := p.decoder.Flush(); len(keys) != 0 {
			return keys, 1, false, nil
		}
	}
	var data []byte
	if console, ok := p.session.(interface{ PollPickerKey() (rune, int, error) }); ok {
		var code rune
		code, repeat, err = console.PollPickerKey()
		if err == nil && repeat > 0 {
			switch code {
			case terminal.PickerKeyUp:
				return []DecodedKey{{Kind: KeyUp}}, repeat, true, nil
			case terminal.PickerKeyDown:
				return []DecodedKey{{Kind: KeyDown}}, repeat, true, nil
			case terminal.PickerKeyEscape:
				return []DecodedKey{{Kind: KeyCancel}}, repeat, true, nil
			default:
				data = utf8.AppendRune(nil, code)
			}
		}
	} else {
		var ready bool
		ready, err = p.session.StdinReadyWithin(0)
		if err == nil && ready {
			var b [1]byte
			_, err = io.ReadFull(p.session.Stdin(), b[:])
			data, repeat = b[:], 1
		}
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			if keys := p.decoder.Flush(); len(keys) != 0 {
				return keys, 1, true, nil
			}
		}
		return nil, 0, false, err
	}
	if len(data) == 0 {
		return nil, 0, false, nil
	}
	keys = p.decoder.Feed(data)
	p.escapeDue = time.Time{}
	if pending := p.decoder.Pending(); len(pending) > 0 && pending[0] == '\x1b' {
		p.escapeDue = now.Add(escGrace)
	}
	return keys, repeat, true, nil
}

// DecodeBytes decodes a complete input buffer, treating a trailing lone ESC
// as cancellation.
func DecodeBytes(b []byte) []DecodedKey {
	var d StreamDecoder
	return append(d.Feed(b), d.Flush()...)
}

// keyForRune classifies one decoded rune: printable runes become KeyRune,
// supported control bytes map to their key, and everything else is
// ignored.
func keyForRune(r rune) (DecodedKey, bool) {
	switch {
	case r < 0x20 || r == 0x7f:
		switch r {
		case '\b', 0x7f:
			return DecodedKey{Kind: KeyBackspace}, true
		case '\t':
			return DecodedKey{Kind: KeyTab}, true
		case '\r', '\n':
			return DecodedKey{Kind: KeyEnter}, true
		case 0x03:
			return DecodedKey{Kind: KeyCancel}, true
		}
		return DecodedKey{}, false
	case unicode.IsPrint(r):
		return DecodedKey{Kind: KeyRune, Rune: r}, true
	}
	return DecodedKey{}, false
}
