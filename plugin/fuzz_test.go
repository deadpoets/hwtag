package plugin

// Parser fuzzing. These need no TPM, so they run in every build, not only
// under -tags agetpmsim.

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/google/go-tpm/tpm2"
)

// A well-formed v2 identity payload (no TPM needed: the private blob is
// opaque to the parser) as the fuzz seed.
func seedIdentity(t testing.TB) []byte {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := k.PublicKey().Bytes()
	pub := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: raw[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: raw[33:]},
		}),
	})
	name := tpm2.TPM2BName{Buffer: make([]byte, 34)}
	i := &Identity{Version: 2, PIN: HasPIN, Public: pub, Private: tpm2.TPM2BPrivate{Buffer: make([]byte, 120)}, SRKName: &name}
	_, b, err := plugin.ParseIdentity(i.String())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func FuzzDecodeIdentity(f *testing.F) {
	f.Add(seedIdentity(f))
	f.Add([]byte{})
	f.Add([]byte{1, 0})
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		i, err := DecodeIdentity(plugin.EncodeIdentity(PluginName, b))
		if err != nil {
			return
		}
		// Whatever parsed must round-trip and expose a usable public key.
		if i.Publickey() == nil {
			t.Fatal("parsed identity without a public key")
		}
		if _, err := i.Recipient(); err != nil {
			t.Fatalf("parsed identity has no recipient: %v", err)
		}
		if _, err := DecodeIdentity(i.String()); err != nil {
			t.Fatalf("re-encoded identity does not parse: %v", err)
		}
		// Unwrap of a foreign stanza must not reach the TPM, whatever the
		// identity's version says (a nil tpm would otherwise panic).
		k, _ := ecdh.P256().GenerateKey(rand.Reader)
		r, _ := NewTagRecipient(k.PublicKey())
		ss, _ := r.Wrap(make([]byte, 16))
		i.Callbacks(nil, nopTPM{}, func() ([]byte, error) { t.Fatal("PIN asked for a foreign stanza"); return nil, nil })
		if _, err := i.Unwrap(ss); !errors.Is(err, age.ErrIncorrectIdentity) {
			t.Fatalf("foreign stanza: %v", err)
		}
	})
}

func FuzzParseTPMRecipient(f *testing.F) {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	f.Add(NewTPMRecipient(k.PublicKey()).String())
	f.Add("age1tpm1")
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseTPMRecipient(s)
		if err != nil {
			return
		}
		if _, err := ParseTPMRecipient(r.String()); err != nil {
			t.Fatalf("re-encoded recipient does not parse: %v", err)
		}
	})
}

// FuzzUnwrapStanza feeds arbitrary stanzas to both identity handlers with a
// TPM that refuses every command: no input may panic, and only a stanza whose
// tag matches may get as far as the TPM.
func FuzzUnwrapStanza(f *testing.F) {
	b := seedIdentity(f)
	id, err := DecodeIdentity(plugin.EncodeIdentity(PluginName, b))
	if err != nil {
		f.Fatal(err)
	}
	r, _ := id.Recipient()
	ss, _ := r.Wrap(make([]byte, 16))
	f.Add(ss[0].Type, ss[0].Args[0], ss[0].Args[1], ss[0].Body)
	old, _ := id.TPMRecipient().Wrap(make([]byte, 16))
	f.Add(old[0].Type, old[0].Args[0], old[0].Args[1], old[0].Body)
	f.Add("p256tag", "", "", []byte{})
	f.Add("tpm-ecc", "AAAA", "", []byte{})
	f.Fuzz(func(t *testing.T, typ, a0, a1 string, body []byte) {
		id.Callbacks(nil, nopTPM{}, func() ([]byte, error) { return []byte("1234"), nil })
		s := &age.Stanza{Type: typ, Args: []string{a0, a1}, Body: body}
		_, _ = id.Unwrap([]*age.Stanza{s})
	})
}

// nopTPM fails every command, so a test can prove the TPM was or was not reached.
type nopTPM struct{}

func (nopTPM) Send([]byte) ([]byte, error) { return nil, errors.New("no TPM in this test") }
func (nopTPM) Close() error                { return nil }
