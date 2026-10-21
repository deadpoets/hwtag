//go:build windows

package plugin

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// openDevice opens the TPM through the TPM Base Services (TBS). Windows has
// no device path to choose, so a non-empty tpmPath is an error.
func openDevice(tpmPath string) (transport.TPMCloser, error) {
	if tpmPath != "" {
		return nil, errors.New("a TPM path is not supported on Windows")
	}
	return windowstpm.Open()
}
