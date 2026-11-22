//go:build agetpmsim

package plugin

import (
	"bytes"
	"io"
	"testing"

	"filippo.io/age"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// lockoutCounter reads the TPM's count of failed authorizations
// (TPM_PT_LOCKOUT_COUNTER), which is the budget a wrong PIN spends.
func lockoutCounter(t *testing.T, tpm transport.TPM) uint32 {
	t.Helper()
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLockoutCounter),
		PropertyCount: 1,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("reading the lockout counter: %v", err)
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		t.Fatalf("reading the lockout counter: %v", err)
	}
	if len(props.TPMProperty) != 1 || props.TPMProperty[0].Property != tpm2.TPMPTLockoutCounter {
		t.Fatal("the TPM did not return its lockout counter")
	}
	return props.TPMProperty[0].Value
}

// The README promises that a decryption asks for the PIN once and never
// retries it: a wrong PIN costs one attempt of the TPM's dictionary-attack
// budget (and of the four TBS allows a standard user on Windows), and a
// second, silent attempt would spend that budget behind the user's back.
//
// Every case hands the identity two stanzas that are both addressed to it,
// which is the input that would make a retry loop show: the same file key
// wrapped twice to the same recipient.
//
// Two things are counted. The PIN callbacks are what the user sees. The TPM's
// own lockout counter is what the promise is about: code that asked once and
// reused the PIN for the second stanza would still show one callback, but
// would spend two attempts.
func TestPINAskedOnce(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	defer tpm.Close()
	SetLogger(io.Discard)

	pin := []byte("123456")
	identity, recipient, err := CreateIdentity(tpm, pin)
	if err != nil {
		t.Fatal(err)
	}
	fileKey := bytes.Repeat([]byte{0x42}, 16)

	// twice wraps the file key two times, so both stanzas match the identity.
	twice := func(t *testing.T, r age.Recipient) []*age.Stanza {
		t.Helper()
		var ss []*age.Stanza
		for range 2 {
			s, err := r.Wrap(fileKey)
			if err != nil {
				t.Fatal(err)
			}
			ss = append(ss, s...)
		}
		return ss
	}

	// Each path is one way a caller reaches the TPM: the plugin's dispatcher
	// (Identity.Unwrap) for both stanza types, and the p256tag identity's
	// UnwrapInto for callers of the Go API.
	paths := []struct {
		name      string
		recipient age.Recipient
		unwrap    func(id *Identity, pin func() ([]byte, error), ss []*age.Stanza) ([]byte, error)
	}{
		{"p256tag", recipient, func(id *Identity, pin func() ([]byte, error), ss []*age.Stanza) ([]byte, error) {
			id.Callbacks(nil, tpm, pin)
			return id.Unwrap(ss)
		}},
		{"p256tag UnwrapInto", recipient, func(id *Identity, pin func() ([]byte, error), ss []*age.Stanza) ([]byte, error) {
			dst := make([]byte, 16)
			err := NewTPMTagIdentity(tpm, pin, id).UnwrapInto(dst, ss)
			return dst, err
		}},
		{"tpm-ecc", identity.TPMRecipient(), func(id *Identity, pin func() ([]byte, error), ss []*age.Stanza) ([]byte, error) {
			id.Callbacks(nil, tpm, pin)
			return id.Unwrap(ss)
		}},
	}

	// A key made without a PIN asks for nothing. This runs before the
	// wrong-PIN cases: their three failures put the simulator into
	// dictionary-attack lockout, which refuses PIN-less keys as well.
	t.Run("no PIN", func(t *testing.T) {
		pinless, r, err := CreateIdentity(tpm, nil)
		if err != nil {
			t.Fatal(err)
		}
		pinless.Callbacks(nil, tpm, func() ([]byte, error) {
			t.Error("PIN asked for a key that has none")
			return nil, nil
		})
		got, err := pinless.Unwrap(twice(t, r))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, fileKey) {
			t.Fatal("wrong file key")
		}
	})

	for _, p := range paths {
		t.Run(p.name+"/right PIN", func(t *testing.T) {
			asked := 0
			before := lockoutCounter(t, tpm)
			got, err := p.unwrap(identity, func() ([]byte, error) { asked++; return pin, nil }, twice(t, p.recipient))
			if err != nil {
				t.Fatal(err)
			}
			if spent := lockoutCounter(t, tpm) - before; spent != 0 {
				t.Fatalf("the right PIN spent %d lockout attempts, want 0", spent)
			}
			if !bytes.Equal(got, fileKey) {
				t.Fatal("wrong file key")
			}
			if asked != 1 {
				t.Fatalf("PIN asked for %d times, want 1", asked)
			}
		})

		// The second stanza must not be tried once the TPM has refused the
		// PIN for the first.
		t.Run(p.name+"/wrong PIN", func(t *testing.T) {
			asked := 0
			before := lockoutCounter(t, tpm)
			_, err := p.unwrap(identity, func() ([]byte, error) { asked++; return []byte("654321"), nil }, twice(t, p.recipient))
			if err == nil {
				t.Fatal("wrong PIN accepted")
			}
			if spent := lockoutCounter(t, tpm) - before; spent != 1 {
				t.Fatalf("a wrong PIN spent %d lockout attempts, want 1", spent)
			}
			if asked != 1 {
				t.Fatalf("PIN asked for %d times after a wrong PIN, want 1", asked)
			}
		})
	}
}
