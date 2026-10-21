//go:build !agetpmsim

package plugin

import (
	"errors"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
)

func useSimulator() bool { return false }

func GetFixedSim() (transport.TPMCloser, error) {
	return nil, errors.New("the TPM simulator is only in test builds (-tags agetpmsim)")
}

// EnvPIN refuses AGE_TPM_PIN: production builds read the PIN from the user,
// never from the environment.
func EnvPIN() (string, error) {
	if _, ok := os.LookupEnv("AGE_TPM_PIN"); ok {
		return "", errors.New("AGE_TPM_PIN is not honoured in this build; unset it and enter the PIN when asked")
	}
	return "", nil
}
