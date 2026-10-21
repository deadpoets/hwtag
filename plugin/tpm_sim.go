//go:build agetpmsim

// The TPM simulator and the AGE_TPM_PIN variable exist only in test builds
// (go test -tags agetpmsim). The simulator uses a fixed, public seed: a key
// generated under it can be decrypted by anyone, so production binaries must
// not be able to select it from the environment.

package plugin

import (
	"io"
	"os"
	"sync"

	sim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

var (
	once sync.Once
	s    transport.TPMCloser
)

// TPM represents a connection to a TPM simulator.
type TPMCloser struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPMCloser) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *TPMCloser) Close() error {
	return t.transport.Close()
}

func GetFixedSim() (transport.TPMCloser, error) {
	var ss *sim.Simulator
	var err error
	once.Do(func() {
		ss, err = sim.GetWithFixedSeedInsecure(123456)
		s = &TPMCloser{ss}
	})
	return s, err
}

func useSimulator() bool { return os.Getenv("_AGE_TPM_SIMULATOR") != "" }

// EnvPIN returns AGE_TPM_PIN, for tests.
func EnvPIN() (string, error) { return os.Getenv("AGE_TPM_PIN"), nil }
