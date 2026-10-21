//go:build !linux && !windows

package plugin

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
)

func openDevice(tpmPath string) (transport.TPMCloser, error) {
	return nil, errors.New("no TPM transport for this platform")
}
