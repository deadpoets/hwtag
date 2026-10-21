hwtag: age plugins for hardware-backed tagged recipients
========================================================

Two [age](https://age-encryption.org) plugins that decrypt files encrypted to
native `age1tag1…` recipients ([p256tag](https://c2sp.org/age#the-tagged-recipient-types),
age ≥ 1.3) with a P-256 key that never leaves a piece of hardware:

| Binary | Key lives in | Platforms |
|---|---|---|
| `age-plugin-tpm` | a TPM 2.0 (key wrapped by the TPM's storage root key) | Linux (`/dev/tpmrm0`), **Windows (TBS)** |
| `age-plugin-ykpiv` | a YubiKey PIV slot, PIN and touch policy *always*, attested at generation | Windows (pure Go), Linux/macOS (cgo, pcsclite) |

Encryption needs no plugin: `age -r age1tag1…` does it with stock age. Only
decryption runs through these binaries, and then the only operation the
hardware performs is one ECDH.

## Origin

hwtag is an independent fork of [age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm)
by Morten Linderud (Foxboron), MIT, from v1.0.1. The git history keeps every
upstream commit. Upstream does not support this fork: **please do not report
problems with hwtag to upstream**, and do not expect fixes here to appear
there. Fixes from upstream are pulled into hwtag one way as they appear.

What hwtag adds on top of v1.0.1:

- Windows support for the TPM plugin, through the TPM Base Services (TBS).
- `age-plugin-ykpiv`: the same p256tag recipient type with a YubiKey PIV key.
- The TPM PIN is proven to the TPM with an HMAC session instead of being sent
  in a password session (where it travels in the clear on the TPM bus).
- The TPM simulator and the `AGE_TPM_PIN` variable exist only in test builds
  (`-tags agetpmsim`). A production binary refuses `AGE_TPM_PIN`.
- Stricter identity and stanza parsing, fuzz tests, and a number of smaller
  fixes (see the git log).

## Install

Pre-built binaries, with sha256 sums, are on the releases page. They are built
with `CGO_ENABLED=0 -trimpath -buildvcs=false` and a pinned Go toolchain, so
building the tag yourself produces byte-identical binaries (Windows and Linux
amd64/arm64 for `age-plugin-tpm`; Windows for `age-plugin-ykpiv`, which needs
cgo and `libpcsclite` elsewhere).

```
go install github.com/deadpoets/hwtag/cmd/age-plugin-tpm@latest
go install github.com/deadpoets/hwtag/cmd/age-plugin-ykpiv@latest
```

The binaries must be on `PATH` for age to find them.

## age-plugin-tpm

```
age-plugin-tpm --generate --pin -o tpm-identity.txt   # new key; PIN typed twice, never echoed
age-plugin-tpm -y tpm-identity.txt                    # print the age1tag1… recipient
age -r age1tag1… -o secret.age secret                 # encrypt with stock age
age -d -i tpm-identity.txt secret.age                 # decrypt: asks for the PIN
```

The identity file holds the key wrapped by the TPM: it is useless on any
other TPM, but keep it, there is no way to recover it from the TPM.

A wrong PIN is refused by the TPM (`TPM_RC_AUTH_FAIL`) and counts toward
its dictionary-attack lockout. **On Windows, TBS additionally locks a
standard (non-elevated) user out after 4 authorization failures**, for the
"standard user lockout duration" (8 hours by default), for every TPM key
of that user, PIN-less ones included. Budget wrong-PIN attempts accordingly.

On Windows the plugin uses the persistent storage root key Windows provisions
at `0x81000001` as the parent, so a TPM clear (`tpm.msc`) destroys every
identity made on that machine.

## age-plugin-ykpiv

```
age-plugin-ykpiv --setup -o yk-identity.txt      # interactive: PIV reset, new key, PIN, PUK, random management key
age-plugin-ykpiv --generate --slot 82 -o yk-identity.txt   # just a new key in a slot (management key asked for)
age-plugin-ykpiv -y yk-identity.txt              # print the recipient
age -d -i yk-identity.txt secret.age             # decrypt: PIN, then touch when it blinks
```

The identity file holds no secret (serial, slot, public key). The key is
generated on the card with PIN policy *always* and touch policy *always*,
and the plugin verifies that by Yubico's attestation at generation and by
the slot's metadata at every decryption; a key that does not match is
refused. Firmware 5.4 or newer.

`--setup` takes a fresh or reused YubiKey to one unseal identity: it resets
the PIV application (FIDO/WebAuthn and OTP are untouched), generates the
key, sets the PIN and PUK you type, and replaces the management key with 24
random bytes that are neither shown nor stored, so nothing in PIV can be
changed again without a reset, which destroys the key. Store the PUK offline.

Windows resets a smart-card connection left idle for about five seconds, so
the PIN is asked for *before* the card is opened; open, verify and ECDH then
run back to back. The card is held exclusively while the plugin runs. The
PIV security state outlives the process on Windows (piv-go disconnects
without a reset), which is why the policies are *always*; unplug and replug
the key after `--setup` or `--generate`.

## Security notes

- Both plugins check the stanza's 4-byte tag before touching any hardware or
  asking for a PIN, so a file for someone else's key never prompts.
- The TPM plugin authorizes the key with an HMAC session salted to the SRK,
  with response encryption: the PIN is never transmitted and the shared
  secret is encrypted on the bus.
- PINs are read through the age plugin protocol (so the age client sees
  them too, by design), live in process memory for the life of one
  short-lived plugin process, and the working copies are wiped after use.
- Nothing is ever taken from the environment or `argv`: not PINs, not the
  management key.
- Tested with the Microsoft TPM 2.0 reference simulator (go-tpm-tools), with
  fuzzing of every parser, and on real hardware: Intel PTT on Windows 11 and
  a YubiKey 5 (firmware 5.7).

## Building and testing

```
go build ./cmd/...                                   # production binaries (no cgo)
CGO_ENABLED=1 go test -race -tags agetpmsim ./...    # with the TPM simulator (needs a C compiler)
GOOS=windows go vet ./...
go test -run '^$' -fuzz FuzzDecodeIdentity ./plugin  # and the other Fuzz* targets
```

## License

MIT. See [LICENSE](LICENSE): the original age-plugin-tpm notice is kept, with
a second line for the hwtag additions.
