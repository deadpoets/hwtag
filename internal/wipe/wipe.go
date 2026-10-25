// Package wipe holds the shared-secret hygiene the two p256tag identities
// have in common.
package wipe

import "filippo.io/hpke/crypto/ecdh"

// KeyExchanger wraps a hardware ECDH key and remembers every shared secret it
// hands to HPKE, so that the caller can wipe them once the HPKE context is
// set up. HPKE uses the ECDH output only to derive its key schedule and does
// not keep it; the copies HPKE derives from it are out of our reach.
type KeyExchanger struct {
	ecdh.KeyExchanger
	out [][]byte
}

var _ ecdh.KeyExchanger = &KeyExchanger{}

// ECDH runs the wrapped exchange and records the result.
func (k *KeyExchanger) ECDH(remote *ecdh.PublicKey) ([]byte, error) {
	z, err := k.KeyExchanger.ECDH(remote)
	if err != nil {
		return nil, err
	}
	k.out = append(k.out, z)
	return z, nil
}

// Wipe zeroes every shared secret returned so far.
func (k *KeyExchanger) Wipe() {
	for _, z := range k.out {
		clear(z)
	}
	k.out = nil
}

// FileKeySize is the size of an age file key, and the size of the buffer
// UnwrapInto writes to.
const FileKeySize = 16

// Into copies fileKey into dst and wipes fileKey. The lengths are checked by
// the caller before any hardware is touched, so a mismatch here means the
// stanza carried a file key of an unexpected size; dst is then left as it was.
func Into(dst, fileKey []byte) bool {
	defer clear(fileKey)
	if len(fileKey) != len(dst) {
		return false
	}
	copy(dst, fileKey)
	return true
}
