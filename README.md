hwtag: age plugins for hardware-backed tagged recipients
========================================================

Two [age](https://age-encryption.org) plugins that decrypt files encrypted to
native `age1tag1…` recipients ([p256tag](https://c2sp.org/age#the-tagged-recipient-types),
age 1.3 or newer) with a P-256 key that never leaves a piece of hardware:

| Binary | The key lives in | Platforms |
|---|---|---|
| `age-plugin-tpm` | a TPM 2.0, wrapped under the TPM's storage root key | Windows (TBS), Linux (`/dev/tpmrm0`) |
| `age-plugin-ykpiv` | a YubiKey PIV slot, PIN and touch policy *always*, attested at generation | Windows (pure Go); Linux and macOS with cgo and pcsclite |

Encryption needs no plugin: `age -r age1tag1…` does it with stock age. Only
decryption goes through these binaries, and the only thing the hardware ever
does is one ECDH.

## Origin and credit

hwtag is a fork of [age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm)
by Morten Linderud (Foxboron), MIT, taken at v1.0.1. The TPM plugin here is
his design and, for the most part, his code: the SRK handling, the identity
format, the session encryption and the p256tag integration are all upstream
work, and the git history keeps every upstream commit under his name. Thank
you.

The fork exists because the two projects want different things from the
development process: upstream does not accept work produced with the help of
language models, and hwtag does. That is a legitimate choice for upstream to
make about its own code, so the Windows support was withdrawn from there and
is maintained here instead. **Please do not report hwtag problems to
upstream**, and do not expect fixes to flow in either direction
automatically; upstream fixes are pulled into hwtag by hand as they appear.

What hwtag adds on top of v1.0.1:

- The TPM plugin builds and runs on Windows, through the TPM Base Services.
- `age-plugin-ykpiv`, a second plugin for the same recipient type with a
  YubiKey PIV key.
- The TPM PIN is proven to the TPM with an HMAC session instead of a
  password session, in which it travels in the clear on the TPM bus.
- The TPM simulator and the `AGE_TPM_PIN` variable exist only in test builds
  (`-tags agetpmsim`); a production binary refuses `AGE_TPM_PIN`.
- Stricter identity and stanza parsing, fuzz tests for every parser, and
  smaller fixes listed in the git log and [CHANGELOG.md](CHANGELOG.md).

## Install

```
go install github.com/deadpoets/hwtag/cmd/age-plugin-tpm@latest
go install github.com/deadpoets/hwtag/cmd/age-plugin-ykpiv@latest
```

Releases carry pre-built binaries with sha256 sums: `age-plugin-tpm` for
Windows and Linux (amd64, arm64) and `age-plugin-ykpiv` for Windows, where it
needs no cgo. They are built with `CGO_ENABLED=0 -trimpath -buildvcs=false`
and the toolchain pinned in `go.mod`, so building a tag yourself gives the
same bytes (add `-ldflags "-X main.version=<tag>"`, which the release build
uses to stamp the version). The binaries must be on `PATH` for age to find
them.

## age-plugin-tpm

```
age-plugin-tpm --generate --pin -o tpm-identity.txt   # new key; the PIN is typed twice, never echoed
age-plugin-tpm -y tpm-identity.txt                    # print the age1tag1… recipient
age -r age1tag1… -o secret.age secret                 # encrypt, with stock age
age -d -i tpm-identity.txt secret.age                 # decrypt: asks for the PIN
```

The identity file holds the key wrapped by the TPM. It is useless on any
other TPM, but keep it: nothing can recover it from the TPM.

A wrong PIN is refused by the TPM (`TPM_RC_AUTH_FAIL`) and counts toward
the TPM's dictionary-attack lockout. On Windows, TBS also locks a standard
(non-elevated) user out after 4 authorization failures, for the "standard
user lockout duration" (8 hours by default), for every TPM key of that user,
PIN-less ones included. Budget wrong-PIN attempts accordingly.

On Windows the parent key is the persistent storage root key Windows
provisions at `0x81000001`, so clearing the TPM (`tpm.msc`) destroys every
identity made on that machine. Linux uses upstream's path unchanged
(`/dev/tpmrm0`, or a transient ECC SRK when there is no persistent one).

## age-plugin-ykpiv

```
age-plugin-ykpiv --setup -o yk-identity.txt                 # interactive: PIV reset, new key, PIN, PUK, random management key
age-plugin-ykpiv --generate --slot 82 -o yk-identity.txt    # only a new key in a slot; asks for the management key
age-plugin-ykpiv -y yk-identity.txt                         # print the recipient
age -d -i yk-identity.txt secret.age                        # decrypt: PIN, then touch when the key blinks
```

The identity file holds no secret: serial, slot and public key. The key is
generated on the card with PIN policy *always* and touch policy *always*;
the plugin checks that through Yubico's attestation at generation and through
the slot's metadata at every decryption, and refuses a key that does not
match. Firmware 5.4 or newer.

`--setup` takes a YubiKey from any state to one identity: it resets the PIV
application (FIDO/WebAuthn and OTP are untouched), generates the key, sets
the PIN and PUK you type, and replaces the management key with 24 random
bytes that are neither shown nor stored, so nothing in PIV can change again
without a reset, which destroys the key. Store the PUK offline.

Windows resets a smart-card connection left idle for about five seconds, so
the PIN is asked for *before* the card is opened; open, verify and ECDH then
run back to back. The card is held exclusively while the plugin runs. Its
security state outlives the process (piv-go disconnects without a reset),
which is one reason the policies are *always*; unplug and replug the key
after `--setup` or `--generate`.

## Security notes

- Both plugins check the stanza's 4-byte tag before touching any hardware or
  asking for a PIN, so a file for someone else's key never prompts.
- The TPM plugin authorizes the key with an HMAC session salted to the SRK,
  with response encryption: the PIN is never transmitted and the shared
  secret is encrypted on the bus.
- PINs arrive through the age plugin protocol (so the age client sees them,
  by design), live in the memory of one short-lived plugin process, and the
  plugin's working copies are wiped after use.
- Nothing is read from the environment or `argv`: not PINs, not the
  management key.
- Tested with the Microsoft TPM 2.0 reference simulator (go-tpm-tools) under
  the race detector, with fuzzing of every parser, and on real hardware: an
  Intel PTT firmware TPM on Windows 11 and a YubiKey 5 (firmware 5.7.4) on
  Windows 11. The Linux TPM path has run only on the simulator in this fork.
  Each release's binaries are exercised on that hardware before the release
  is tagged.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Building and testing

```
make build          # production binaries, no cgo
make test           # with the TPM simulator and the race detector (needs a C compiler)
make check          # vet (linux and windows), gofmt, staticcheck
make fuzz           # the five fuzz targets, 30 s each
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

MIT. [LICENSE](LICENSE) keeps the original age-plugin-tpm notice and adds a
line for the hwtag additions.
