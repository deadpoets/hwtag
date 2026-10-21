package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
)

func marshalPub(k crypto.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil
	}
	return b
}

func ecdsaToECDH(k crypto.PublicKey) (*ecdh.PublicKey, error) {
	e, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key: %T", k)
	}
	return e.ECDH()
}
