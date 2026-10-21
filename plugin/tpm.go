package plugin

import (
	"crypto/ecdh"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Setup a NewTPMDevice
func NewTPM(tpmPath string) (transport.TPMCloser, error) {
	if useSimulator() {
		return GetFixedSim()
	}

	return openDevice(tpmPath)
}

// shadow the unexported interface from go-tpm
type handle interface {
	HandleValue() uint32
	KnownName() *tpm2.TPM2BName
}

// Helper to flush handles
func FlushHandle(tpm transport.TPM, h handle) {
	flushSrk := tpm2.FlushContext{FlushHandle: h}
	flushSrk.Execute(tpm)
}

func PublicToECDH(b tpm2.TPM2BPublic) (*ecdh.PublicKey, error) {
	pub, err := b.Contents()
	if err != nil {
		return nil, err
	}

	parameters, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}

	eccdeets, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}

	return tpm2.ECDHPub(parameters, eccdeets)
}
