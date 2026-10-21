package ykpiv

import (
	"errors"
	"testing"

	"filippo.io/age"
)

func FuzzUnmarshal(f *testing.F) {
	b, _ := newIdentity(f).Marshal()
	f.Add(b)
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, b []byte) {
		i, err := Unmarshal(b)
		if err != nil {
			return
		}
		c, err := i.Marshal()
		if err != nil {
			t.Fatalf("parsed identity does not marshal: %v", err)
		}
		j, err := Unmarshal(c)
		if err != nil || j.Serial != i.Serial || j.Slot.Key != i.Slot.Key || !j.Pub.Equal(i.Pub) {
			t.Fatalf("round trip: %v", err)
		}
		if _, err := i.Recipient(); err != nil {
			t.Fatalf("parsed identity has no recipient: %v", err)
		}
	})
}

// FuzzUnwrap: arbitrary stanzas must never panic and must never ask for the
// PIN unless the tag matches our key, which the fuzzer cannot forge.
func FuzzUnwrap(f *testing.F) {
	i := newIdentity(f)
	ss := wrapTo(f, i)
	f.Add(ss[0].Type, ss[0].Args[0], ss[0].Args[1], ss[0].Body)
	f.Add("p256tag", "", "", []byte{})
	f.Add("x25519", "AAAA", "AAAA", []byte{})
	f.Fuzz(func(t *testing.T, typ, a0, a1 string, body []byte) {
		asked := false
		i.PIN = func() (string, error) { asked = true; return "", errors.New("stop") }
		s := &age.Stanza{Type: typ, Args: []string{a0, a1}, Body: body}
		_, err := i.Unwrap([]*age.Stanza{s})
		if asked && !(typ == ss[0].Type && a0 == ss[0].Args[0] && a1 == ss[0].Args[1]) {
			t.Fatalf("PIN asked for a stanza that is not ours: %v", err)
		}
	})
}
