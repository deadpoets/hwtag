package plugin

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/tag"
	"filippo.io/hpke"
	"github.com/deadpoets/hwtag/internal/wipe"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMTagIdentity implements the p256tag identity handler
type TPMTagIdentity struct {
	tpm      transport.TPMCloser
	identity *Identity
	pin      func() ([]byte, error)
}

func NewTPMTagIdentity(tpm transport.TPMCloser, pin func() ([]byte, error), identity *Identity) *TPMTagIdentity {
	return &TPMTagIdentity{tpm, identity, pin}
}

var _ age.Identity = &TPMTagIdentity{}

func (t *TPMTagIdentity) unwrap(block *age.Stanza) ([]byte, error) {
	if block.Type != "p256tag" {
		return nil, age.ErrIncorrectIdentity
	}
	// The same checks as age's reference p256tag identity: exactly two
	// arguments, a 4-byte tag and a 65-byte uncompressed point. A stanza that
	// fails them is malformed, not foreign. The body's length is left to the
	// AEAD (age file keys are 16 bytes, but Wrap accepts any length).
	if len(block.Args) != 2 {
		return nil, fmt.Errorf("malformed stanza")
	}

	tag, err := b64Decode(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("malformed tag: %v", err)
	}
	if len(tag) != 4 {
		return nil, fmt.Errorf("invalid tag length: %d", len(tag))
	}

	sessionKey, err := b64Decode(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("malformed encapsulated key: %v", err)
	}
	if len(sessionKey) != 65 {
		return nil, fmt.Errorf("invalid encapsulated key length: %d", len(sessionKey))
	}

	rsp, err := t.identity.Recipient()
	if err != nil {
		return nil, fmt.Errorf("unwrap: failed to get recipient from identity %v", err)
	}

	itag, err := rsp.Tag(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("unwrap: failed to get tag from recipient: %v", err)
	}

	// Check if we are dealing with the correct key
	if subtle.ConstantTimeCompare(tag, itag) != 1 {
		return nil, age.ErrIncorrectIdentity
	}
	var pin []byte
	if t.identity.HasPIN() {
		pin, err = t.pin()
		if err != nil {
			return nil, fmt.Errorf("failed to get pin: %v", err)
		}
		// Work on our own copy and wipe it once the TPM has authorized the
		// ECDH; the callback's slice stays the caller's (tests reuse it).
		pin = bytes.Clone(pin)
		defer clear(pin)
	}

	// The ECDH runs inside NewRecipient; wipe its output as soon as the HPKE
	// context exists.
	kx := &wipe.KeyExchanger{KeyExchanger: NewTPMKeyExchange(t.tpm, pin, t.identity)}
	k, err := hpke.NewDHKEMPrivateKey(kx)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap file key: %v", err)
	}
	r, err := hpke.NewRecipient(sessionKey, k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("age-encryption.org/p256tag"))
	kx.Wipe()
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap file key: %v", err)
	}
	return r.Open(nil, block.Body)
}

func (t *TPMTagIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		fileKey, err := t.unwrap(s)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

// UnwrapInto is Unwrap for callers that keep the file key in memory they
// manage themselves, such as a locked buffer. dst must be exactly 16 bytes,
// the age file key size; that is checked before the TPM is touched or a PIN
// is asked for. On success the key is in dst and hwtag's own copies of it and
// of the ECDH shared secret have been wiped; on error dst is left as it was.
//
// This narrows the time the key spends on the Go heap; it does not close it.
// Copies made inside go-tpm, hpke and the Go runtime are out of reach.
func (t *TPMTagIdentity) UnwrapInto(dst []byte, stanzas []*age.Stanza) error {
	if len(dst) != wipe.FileKeySize {
		return fmt.Errorf("file key buffer is %d bytes, want %d", len(dst), wipe.FileKeySize)
	}
	fileKey, err := t.Unwrap(stanzas)
	if err != nil {
		return err
	}
	if !wipe.Into(dst, fileKey) {
		return errors.New("stanza holds a file key of unexpected size")
	}
	return nil
}

func (t *TPMTagIdentity) Recipient() *tag.Recipient {
	resp, err := NewTagRecipient(t.identity.publickey)
	if err != nil {
		panic("this is unexpected")
	}
	return resp
}
