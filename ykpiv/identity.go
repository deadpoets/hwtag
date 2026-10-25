// Package ykpiv implements an age identity for a P-256 key held in a YubiKey
// PIV slot, decrypting the native p256tag recipient type (age >= 1.3,
// https://c2sp.org/age#the-tagged-recipient-types).
//
// Encryption needs no plugin: stock age encrypts to the age1tag1... recipient.
// Unwrap follows filippo.io/age/tag/internal/tagtest.ClassicIdentity line for
// line; the only difference is that the ECDH runs on the card.
package ykpiv

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/tag"
	"filippo.io/hpke"
	"filippo.io/nistec"
	"github.com/deadpoets/hwtag/internal/wipe"
	"github.com/go-piv/piv-go/v2/piv"
)

// Name is the plugin name: identities are AGE-PLUGIN-YKPIV-1..., the binary is
// age-plugin-ykpiv.
const Name = "ykpiv"

const (
	formatVersion = 1
	// version(1) | serial(4) | slot(1) | compressed P-256 point(33)
	identityLen = 1 + 4 + 1 + 33
)

// Identity names a key on a specific YubiKey. It holds no secret.
type Identity struct {
	Serial uint32
	Slot   piv.Slot
	Pub    *ecdh.PublicKey

	// PIN returns the PIV PIN when the card asks for it.
	PIN func() (string, error)
	// Notify shows a message to the user (the touch prompt).
	Notify func(string) error
}

var _ age.Identity = &Identity{}

// SlotFor accepts the retired key-management slots 0x82-0x95 and 9d.
func SlotFor(key uint32) (piv.Slot, error) {
	if key == piv.SlotKeyManagement.Key {
		return piv.SlotKeyManagement, nil
	}
	if s, ok := piv.RetiredKeyManagementSlot(key); ok {
		return s, nil
	}
	return piv.Slot{}, fmt.Errorf("slot %#x is not a key-management slot (9d or 82-95)", key)
}

func compressed(pub *ecdh.PublicKey) ([]byte, error) {
	p, err := nistec.NewP256Point().SetBytes(pub.Bytes())
	if err != nil {
		return nil, err
	}
	return p.BytesCompressed(), nil
}

// Marshal returns the identity's Bech32 payload.
func (i *Identity) Marshal() ([]byte, error) {
	c, err := compressed(i.Pub)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, identityLen)
	b = append(b, formatVersion)
	b = binary.BigEndian.AppendUint32(b, i.Serial)
	b = append(b, byte(i.Slot.Key))
	return append(b, c...), nil
}

// Unmarshal parses an identity's Bech32 payload.
func Unmarshal(data []byte) (*Identity, error) {
	if len(data) != identityLen {
		return nil, fmt.Errorf("invalid identity length: %d", len(data))
	}
	if data[0] != formatVersion {
		return nil, fmt.Errorf("unsupported identity version: %d", data[0])
	}
	slot, err := SlotFor(uint32(data[5]))
	if err != nil {
		return nil, err
	}
	p, err := nistec.NewP256Point().SetBytes(data[6:])
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", err)
	}
	pub, err := ecdh.P256().NewPublicKey(p.Bytes())
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", err)
	}
	return &Identity{Serial: binary.BigEndian.Uint32(data[1:5]), Slot: slot, Pub: pub}, nil
}

// Recipient returns the age1tag1... recipient for this identity.
func (i *Identity) Recipient() (*tag.Recipient, error) {
	c, err := compressed(i.Pub)
	if err != nil {
		return nil, err
	}
	return tag.NewClassicRecipient(c)
}

func decodeString(s string) ([]byte, error) {
	return base64.RawStdEncoding.Strict().DecodeString(s)
}

// Unwrap implements age.Identity.
func (i *Identity) Unwrap(ss []*age.Stanza) ([]byte, error) {
	rcpt, err := i.Recipient()
	if err != nil {
		return nil, err
	}
	for _, s := range ss {
		if s.Type != "p256tag" {
			continue
		}
		if len(s.Args) != 2 {
			return nil, fmt.Errorf("malformed stanza")
		}
		tagArg, err := decodeString(s.Args[0])
		if err != nil {
			return nil, fmt.Errorf("malformed tag: %v", err)
		}
		if len(tagArg) != 4 {
			return nil, fmt.Errorf("invalid tag length: %d", len(tagArg))
		}
		enc, err := decodeString(s.Args[1])
		if err != nil {
			return nil, fmt.Errorf("malformed encapsulated key: %v", err)
		}
		if len(enc) != 65 {
			return nil, fmt.Errorf("invalid encapsulated key length: %d", len(enc))
		}
		if len(s.Body) != 32 {
			return nil, fmt.Errorf("invalid encrypted file key length: %d", len(s.Body))
		}

		expTag, err := rcpt.Tag(enc)
		if err != nil {
			return nil, fmt.Errorf("failed to compute tag: %v", err)
		}
		if subtle.ConstantTimeCompare(tagArg, expTag[:4]) != 1 {
			return nil, age.ErrIncorrectIdentity
		}

		// The stanza is ours. Ask for the PIN before opening the card: on
		// Windows the smart card service resets a connection left idle
		// during a prompt (SCARD_W_RESET_CARD), so open, verify and ECDH
		// must run back to back.
		if i.PIN == nil {
			return nil, errors.New("no PIN source")
		}
		pin, err := i.PIN()
		if err != nil {
			return nil, err
		}
		kx, err := i.open(pin)
		if err != nil {
			return nil, err
		}
		defer kx.yk.Close()
		// The ECDH runs inside NewRecipient; wipe its output as soon as the
		// HPKE context exists.
		wkx := &wipe.KeyExchanger{KeyExchanger: kx}
		k, err := hpke.NewDHKEMPrivateKey(wkx)
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap file key: %v", err)
		}
		r, err := hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("age-encryption.org/p256tag"))
		wkx.Wipe()
		if err != nil {
			return nil, fmt.Errorf("failed to unwrap file key: %v", err)
		}
		return r.Open(nil, s.Body)
	}
	return nil, age.ErrIncorrectIdentity
}

// UnwrapInto is Unwrap for callers that keep the file key in memory they
// manage themselves, such as a locked buffer. dst must be exactly 16 bytes,
// the age file key size; that is checked before the card is opened or a PIN
// is asked for. On success the key is in dst and hwtag's own copies of it and
// of the ECDH shared secret have been wiped; on error dst is left as it was.
//
// This narrows the time the key spends on the Go heap; it does not close it.
// Copies made inside piv-go, hpke and the Go runtime are out of reach, and the
// PIN is a string end to end (age's plugin protocol and piv-go both take one).
func (i *Identity) UnwrapInto(dst []byte, ss []*age.Stanza) error {
	if len(dst) != wipe.FileKeySize {
		return fmt.Errorf("file key buffer is %d bytes, want %d", len(dst), wipe.FileKeySize)
	}
	fileKey, err := i.Unwrap(ss)
	if err != nil {
		return err
	}
	if !wipe.Into(dst, fileKey) {
		return errors.New("stanza holds a file key of unexpected size")
	}
	return nil
}

// OpenCard opens the YubiKey with the given serial. With serial 0 exactly one
// YubiKey must be present.
func OpenCard(serial uint32) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("listing smart cards: %v", err)
	}
	var found *piv.YubiKey
	var lastErr error
	n := 0
	for _, c := range cards {
		yk, err := piv.Open(c)
		if err != nil {
			// Non-YubiKey readers fail here too, so this is only a hint,
			// but "sharing violation" is the answer when another process
			// holds the card.
			lastErr = fmt.Errorf("%s: %v", c, err)
			continue
		}
		s, err := yk.Serial()
		if err != nil || (serial != 0 && s != serial) {
			yk.Close()
			continue
		}
		n++
		if found != nil {
			found.Close()
		}
		found = yk
	}
	switch {
	case found == nil && lastErr != nil:
		return nil, fmt.Errorf("no YubiKey could be opened (is another program using it?): %v", lastErr)
	case found == nil && serial != 0:
		return nil, fmt.Errorf("YubiKey with serial %d not found; is it plugged in?", serial)
	case found == nil:
		return nil, errors.New("no YubiKey found")
	case n > 1:
		found.Close()
		return nil, errors.New("more than one YubiKey present; pass --serial")
	}
	return found, nil
}

// open finds the card and checks that the slot still holds this identity's
// key, generated on the card with touch always, before any PIN is asked for.
func (i *Identity) open(pin string) (*keyExchange, error) {
	yk, err := OpenCard(i.Serial)
	if err != nil {
		return nil, err
	}
	ki, err := yk.KeyInfo(i.Slot)
	if err != nil {
		yk.Close()
		return nil, fmt.Errorf("reading slot %x metadata: %v", i.Slot.Key, err)
	}
	pub, ok := ki.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		yk.Close()
		return nil, fmt.Errorf("slot %x does not hold a P-256 key", i.Slot.Key)
	}
	pubECDH, err := pub.ECDH()
	if err != nil || !pubECDH.Equal(i.Pub) {
		yk.Close()
		return nil, fmt.Errorf("slot %x holds a different key than this identity", i.Slot.Key)
	}
	if ki.Origin != piv.OriginGenerated || ki.TouchPolicy != piv.TouchPolicyAlways || ki.PINPolicy != piv.PINPolicyAlways {
		yk.Close()
		return nil, fmt.Errorf("slot %x key is not card-generated with PIN and touch policy always", i.Slot.Key)
	}
	priv, err := yk.PrivateKey(i.Slot, pub, piv.KeyAuth{PIN: pin, PINPolicy: ki.PINPolicy})
	if err != nil {
		yk.Close()
		return nil, err
	}
	ek, ok := priv.(*piv.ECDSAPrivateKey)
	if !ok {
		yk.Close()
		return nil, fmt.Errorf("unexpected key type %T", priv)
	}
	return &keyExchange{yk: yk, priv: ek, pub: i.Pub, notify: i.Notify}, nil
}

// keyExchange is an hpke ecdh.KeyExchanger whose private half is on the card.
type keyExchange struct {
	yk     *piv.YubiKey
	priv   *piv.ECDSAPrivateKey
	pub    *ecdh.PublicKey
	notify func(string) error
}

func (k *keyExchange) PublicKey() *ecdh.PublicKey { return k.pub }
func (k *keyExchange) Curve() ecdh.Curve          { return ecdh.P256() }

func (k *keyExchange) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	if k.notify != nil {
		if err := k.notify("Touch your YubiKey when it blinks."); err != nil {
			return nil, err
		}
	}
	z, err := k.priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("YubiKey ECDH: %v", err)
	}
	if len(z) != 32 {
		return nil, fmt.Errorf("YubiKey ECDH: unexpected shared secret length %d", len(z))
	}
	return z, nil
}
