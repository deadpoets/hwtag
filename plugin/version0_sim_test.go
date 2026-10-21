//go:build agetpmsim

package plugin

import (
	"crypto/rand"
	"testing"

	"filippo.io/age/plugin"
)

// A crafted identity with Version 0 (neither 1 nor >1) reaches the SRK name
// comparison with SRKName == nil.
func TestVersion0IdentityNoPanic(t *testing.T) {
	tpm, err := GetFixedSim()
	if err != nil {
		t.Fatal(err)
	}
	b := seedIdentity(t)
	b[0] = 0
	id, err := DecodeIdentity(plugin.EncodeIdentity(PluginName, b))
	if err != nil {
		t.Skipf("version 0 rejected by the parser: %v", err)
	}
	r, _ := id.Recipient()
	fk := make([]byte, 16)
	rand.Read(fk)
	ss, _ := r.Wrap(fk)
	id.Callbacks(nil, tpm, func() ([]byte, error) { return []byte("1234"), nil })
	_, err = id.Unwrap(ss)
	t.Logf("unwrap of a version-0 identity: %v", err)
}
