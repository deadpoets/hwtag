package wipe

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestKeyExchangerWipe(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := &KeyExchanger{KeyExchanger: priv}
	z, err := k.ECDH(peer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := peer.ECDH(priv.PublicKey())
	if !bytes.Equal(z, want) {
		t.Fatal("wrapped ECDH disagrees with the plain one")
	}
	k.Wipe()
	if !bytes.Equal(z, make([]byte, len(z))) {
		t.Fatal("shared secret not wiped")
	}
}

func TestInto(t *testing.T) {
	dst := make([]byte, FileKeySize)
	key := bytes.Repeat([]byte{7}, FileKeySize)
	if !Into(dst, key) {
		t.Fatal("Into refused a key of the right size")
	}
	if !bytes.Equal(dst, bytes.Repeat([]byte{7}, FileKeySize)) || !bytes.Equal(key, make([]byte, FileKeySize)) {
		t.Fatal("key not copied, or source not wiped")
	}

	dst = make([]byte, FileKeySize)
	long := bytes.Repeat([]byte{9}, FileKeySize+1)
	if Into(dst, long) {
		t.Fatal("Into accepted a key of the wrong size")
	}
	if !bytes.Equal(dst, make([]byte, FileKeySize)) || !bytes.Equal(long, make([]byte, len(long))) {
		t.Fatal("dst written, or source not wiped, on a size mismatch")
	}
}
