package picker

import (
	"reflect"
	"testing"

	"warden/internal/model"
)

func TestStateFiltersNameAndHostCaseInsensitively(t *testing.T) {
	conns := []model.SSHConnection{
		{ID: 1, Name: "prod-web", Host: "10.0.0.1"},
		{ID: 2, Name: "bastion", Host: "edge.example.test"},
	}
	state := NewState(conns)
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'E'})
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'D'})
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'G'})
	if got := state.Filtered(); len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("Filtered() = %#v, want bastion", got)
	}
}

func TestStateNavigationAndQueryReset(t *testing.T) {
	state := NewState([]model.SSHConnection{{ID: 1, Name: "alpha"}, {ID: 2, Name: "beta"}})
	state = state.Apply(DecodedKey{Kind: KeyDown})
	selected, ok := state.Selected()
	if !ok || selected.ID != 2 {
		t.Fatalf("selected = %#v, %t; want beta, true", selected, ok)
	}
	state = state.Apply(DecodedKey{Kind: KeyRune, Rune: 'a'})
	state = state.Apply(DecodedKey{Kind: KeyBackspace})
	selected, ok = state.Selected()
	if !ok || selected.ID != 1 {
		t.Fatalf("selection after filter reset = %#v, %t; want alpha, true", selected, ok)
	}
}

func TestDecodeBytesRecognizesNavigationAndCancel(t *testing.T) {
	got := DecodeBytes([]byte("a\x7f\x1b[A\x1b[B\r\x03\x1b"))
	want := []DecodedKey{
		{Kind: KeyRune, Rune: 'a'}, {Kind: KeyBackspace}, {Kind: KeyUp},
		{Kind: KeyDown}, {Kind: KeyEnter}, {Kind: KeyCancel}, {Kind: KeyCancel},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeBytes() = %#v, want %#v", got, want)
	}
}

func TestStreamDecoderBuffersPartialArrow(t *testing.T) {
	var d StreamDecoder
	if got := d.Feed([]byte("\x1b[")); len(got) != 0 {
		t.Fatalf("Feed(\"\\x1b[\") = %#v, want no keys yet", got)
	}
	if got := d.Feed([]byte("A")); len(got) != 1 || got[0].Kind != KeyUp {
		t.Fatalf("Feed(\"A\") = %#v, want KeyUp", got)
	}
}
