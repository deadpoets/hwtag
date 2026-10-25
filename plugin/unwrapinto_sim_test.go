//go:build agetpmsim

package plugin

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"filippo.io/age"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestUnwrapInto(t *testing.T) {
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
	wrap := func(fileKey []byte) []*age.Stanza {
		t.Helper()
		ss, err := recipient.Wrap(fileKey)
		if err != nil {
			t.Fatal(err)
		}
		return ss
	}
	fileKey := bytes.Repeat([]byte{0x42}, 16)
	marker := bytes.Repeat([]byte{0xaa}, 16)

	t.Run("ok", func(t *testing.T) {
		ti := NewTPMTagIdentity(tpm, func() ([]byte, error) { return pin, nil }, identity)
		dst := make([]byte, 16)
		if err := ti.UnwrapInto(dst, wrap(fileKey)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dst, fileKey) {
			t.Fatal("wrong file key")
		}
	})

	// The buffer size is checked before the PIN is asked for, so a caller's
	// mistake costs no dictionary-attack attempt.
	t.Run("buffer size", func(t *testing.T) {
		ti := NewTPMTagIdentity(tpm, func() ([]byte, error) {
			t.Fatal("PIN requested")
			return nil, nil
		}, identity)
		for _, n := range []int{0, 15, 17, 32} {
			if err := ti.UnwrapInto(make([]byte, n), wrap(fileKey)); err == nil {
				t.Errorf("%d-byte buffer accepted", n)
			}
		}
	})

	t.Run("wrong PIN", func(t *testing.T) {
		ti := NewTPMTagIdentity(tpm, func() ([]byte, error) { return []byte("654321"), nil }, identity)
		dst := bytes.Clone(marker)
		if err := ti.UnwrapInto(dst, wrap(fileKey)); err == nil {
			t.Fatal("wrong PIN accepted")
		}
		if !bytes.Equal(dst, marker) {
			t.Fatal("dst written on error")
		}
	})

	t.Run("foreign stanza", func(t *testing.T) {
		_, otherRecipient, err := CreateIdentity(tpm, nil)
		if err != nil {
			t.Fatal(err)
		}
		ss, err := otherRecipient.Wrap(fileKey)
		if err != nil {
			t.Fatal(err)
		}
		ti := NewTPMTagIdentity(tpm, func() ([]byte, error) {
			t.Fatal("PIN requested for a foreign stanza")
			return nil, nil
		}, identity)
		dst := bytes.Clone(marker)
		if err := ti.UnwrapInto(dst, ss); !errors.Is(err, age.ErrIncorrectIdentity) {
			t.Fatalf("got %v, want ErrIncorrectIdentity", err)
		}
		if !bytes.Equal(dst, marker) {
			t.Fatal("dst written on error")
		}
	})

	// Unwrap accepts any wrapped length; UnwrapInto only an age file key.
	t.Run("odd file key size", func(t *testing.T) {
		ti := NewTPMTagIdentity(tpm, func() ([]byte, error) { return pin, nil }, identity)
		dst := bytes.Clone(marker)
		if err := ti.UnwrapInto(dst, wrap(make([]byte, 22))); err == nil {
			t.Fatal("22-byte file key accepted")
		}
		if !bytes.Equal(dst, marker) {
			t.Fatal("dst written on error")
		}
	})
}
