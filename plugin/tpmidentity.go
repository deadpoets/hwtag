package plugin

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"filippo.io/age"
	"filippo.io/nistec"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMIdentity implements the tpm identity handler
type TPMIdentity struct {
	tpm      transport.TPMCloser
	identity *Identity
	pin      func() ([]byte, error)
}

func NewTPMIdentity(tpm transport.TPMCloser, pin func() ([]byte, error), identity *Identity) *TPMIdentity {
	return &TPMIdentity{tpm, identity, pin}
}

var _ age.Identity = &TPMIdentity{}

func (t *TPMIdentity) unwrap(block *age.Stanza) ([]byte, error) {
	if block.Type != "tpm-ecc" {
		return nil, age.ErrIncorrectIdentity
	}
	// tpm-ecc stanzas were only ever written by this code: two arguments, a
	// 4-byte tag and a 33-byte compressed point. The body is the AEAD's.
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
		return nil, fmt.Errorf("malformed session key: %v", err)
	}
	if len(sessionKey) != 33 {
		return nil, fmt.Errorf("invalid session key length: %d", len(sessionKey))
	}

	// The tpm-ecc recipient uses the checksum of the key, with the first 4 bytes
	// as the tag
	sum := sha256.Sum256(t.identity.publickey.Bytes())

	// Check if we are dealing with the correct key
	if subtle.ConstantTimeCompare(tag, sum[:4]) != 1 {
		return nil, age.ErrIncorrectIdentity
	}

	var pin []byte
	if t.identity.HasPIN() {
		pin, err = t.pin()
		if err != nil {
			return nil, fmt.Errorf("failed to get pin: %v", err)
		}
		pin = bytes.Clone(pin)
		defer clear(pin)
	}

	p, err := nistec.NewP256Point().SetBytes(sessionKey)
	if err != nil {
		return nil, err
	}
	sessionKeyECDH, err := ecdh.P256().NewPublicKey(p.Bytes())
	if err != nil {
		return nil, err
	}

	exchange := NewTPMKeyExchange(t.tpm, pin, t.identity)
	sharedSecret, err := exchange.ECDH(sessionKeyECDH)
	if err != nil {
		return nil, err
	}

	// Unwrap the key with the kdf/chacha20
	return UnwrapKey(sessionKeyECDH, t.identity.publickey, sharedSecret, block.Body)
}

func (t *TPMIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
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
