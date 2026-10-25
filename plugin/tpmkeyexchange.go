package plugin

import (
	"fmt"

	"filippo.io/hpke/crypto/ecdh"
	"filippo.io/nistec"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type TPMKeyExchange struct {
	tpm transport.TPMCloser
	i   *Identity
	pin []byte
}

var _ ecdh.KeyExchanger = &TPMKeyExchange{}

func NewTPMKeyExchange(tpm transport.TPMCloser, pin []byte, i *Identity) *TPMKeyExchange {
	return &TPMKeyExchange{
		tpm, i, pin,
	}
}

func (t *TPMKeyExchange) PublicKey() *ecdh.PublicKey {
	return t.i.Publickey()
}

func (t *TPMKeyExchange) Curve() ecdh.Curve {
	// TODO: We can derive this from the TPM key. But this is never going to change.
	return ecdh.P256()
}

func (t *TPMKeyExchange) ECDH(remoteKey *ecdh.PublicKey) ([]byte, error) {
	// We'll be using the SRK for the session encryption, and we need it as the
	// parent for our application key. Make sure it's created and available.
	srkHandle, srkPublic, err := AcquireIdentitySRK(t.tpm, t.i)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(t.tpm, srkHandle)

	// We load the identity into the TPM, using the SRK parent.
	handle, err := LoadIdentityWithParent(t.tpm, *srkHandle, t.i)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(t.tpm, handle.Handle)

	// Authorize the key with an HMAC session that knows the PIN, salted to the
	// SRK and with response encryption. A password session (TPM_RS_PW) would
	// put the PIN itself in the command's authorization area, in the clear on
	// the TPM bus; the HMAC session proves the PIN without sending it, and
	// encrypts the shared secret coming back. A wrong PIN still fails with
	// TPM_RC_AUTH_FAIL and counts toward the dictionary-attack lockout.
	handle.Auth = tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
		tpm2.Auth(t.pin),
		tpm2.AESEncryption(128, tpm2.EncryptOut),
		tpm2.Salted(srkHandle.Handle, *srkPublic))

	p, err := nistec.NewP256Point().SetBytes(remoteKey.Bytes())
	if err != nil {
		return nil, err
	}

	// Get X/Y points from sessionkey
	x, y := xyECC(p.Bytes())

	// ECDHZGen command for the TPM, turns the sesion key into something we understand.
	ecdh := tpm2.ECDHZGen{
		KeyHandle: *handle,
		InPoint: tpm2.New2B(
			tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: x},
				Y: tpm2.TPM2BECCParameter{Buffer: y},
			},
		),
	}

	// Execute the ECDHZGen command. The auth session above also encrypts the
	// private part going out of the TPM, which is the shared secret we feed
	// to the KDF.
	ecdhRsp, err := ecdh.Execute(t.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed ecdhzgen: %v", err)
	}

	shared, err := ecdhRsp.OutPoint.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed getting ecdh point: %v", err)
	}

	// Only X is the shared secret; Y follows from it, so don't leave it about.
	clear(shared.Y.Buffer)
	return shared.X.Buffer, nil
}
