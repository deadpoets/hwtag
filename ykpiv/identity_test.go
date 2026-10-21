package ykpiv

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/age"
	"github.com/go-piv/piv-go/v2/piv"
)

func newIdentity(t *testing.T) *Identity {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	slot, _ := piv.RetiredKeyManagementSlot(0x82)
	return &Identity{Serial: 38788548, Slot: slot, Pub: k.PublicKey()}
}

func wrapTo(t *testing.T, i *Identity) []*age.Stanza {
	t.Helper()
	r, err := i.Recipient()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := r.Wrap(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	return ss
}

func TestMarshalRoundTrip(t *testing.T) {
	i := newIdentity(t)
	b, err := i.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	j, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if j.Serial != i.Serial || j.Slot.Key != i.Slot.Key || !j.Pub.Equal(i.Pub) {
		t.Fatalf("round trip mismatch")
	}
}

func TestUnmarshalRejects(t *testing.T) {
	b, _ := newIdentity(t).Marshal()
	cases := map[string]func([]byte) []byte{
		"short":     func(b []byte) []byte { return b[:len(b)-1] },
		"long":      func(b []byte) []byte { return append(b, 0) },
		"version":   func(b []byte) []byte { b[0] = 2; return b },
		"slot 9a":   func(b []byte) []byte { b[5] = 0x9a; return b },
		"slot 96":   func(b []byte) []byte { b[5] = 0x96; return b },
		"bad point": func(b []byte) []byte { b[6] = 0x05; return b },
		"x >= p": func(b []byte) []byte {
			for k := 7; k < len(b); k++ {
				b[k] = 0xff
			}
			return b
		},
	}
	for name, mut := range cases {
		c := append([]byte(nil), b...)
		if _, err := Unmarshal(mut(c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A stanza for someone else's key must be skipped before any PIN prompt.
func TestUnwrapForeignStanzaNoPrompt(t *testing.T) {
	ours, theirs := newIdentity(t), newIdentity(t)
	ours.PIN = func() (string, error) {
		t.Fatal("PIN requested for a foreign stanza")
		return "", nil
	}
	if _, err := ours.Unwrap(wrapTo(t, theirs)); !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("got %v, want ErrIncorrectIdentity", err)
	}
}

// For our own stanza the PIN is asked for first, before the card is opened
// (Windows resets an idle card connection after ~5 s).
func TestUnwrapOwnStanzaPromptsBeforeCard(t *testing.T) {
	i := newIdentity(t)
	stop := errors.New("stop before card")
	asked := false
	i.PIN = func() (string, error) { asked = true; return "", stop }
	if _, err := i.Unwrap(wrapTo(t, i)); !errors.Is(err, stop) || !asked {
		t.Fatalf("got %v (asked=%v), want the PIN prompt's error", err, asked)
	}
}

func TestUnwrapMalformed(t *testing.T) {
	i := newIdentity(t)
	i.PIN = func() (string, error) { t.Fatal("PIN requested"); return "", nil }
	good := wrapTo(t, i)[0]
	cases := map[string]func(s *age.Stanza){
		"args":     func(s *age.Stanza) { s.Args = s.Args[:1] },
		"tag len":  func(s *age.Stanza) { s.Args[0] = "AAAA" },
		"enc len":  func(s *age.Stanza) { s.Args[1] = "AAAA" },
		"body len": func(s *age.Stanza) { s.Body = s.Body[:31] },
		"b64":      func(s *age.Stanza) { s.Args[0] = "!!!!" },
	}
	for name, mut := range cases {
		s := &age.Stanza{Type: good.Type, Args: append([]string(nil), good.Args...), Body: append([]byte(nil), good.Body...)}
		mut(s)
		if _, err := i.Unwrap([]*age.Stanza{s}); err == nil || errors.Is(err, age.ErrIncorrectIdentity) {
			t.Errorf("%s: got %v, want a malformed-stanza error", name, err)
		}
	}
}
