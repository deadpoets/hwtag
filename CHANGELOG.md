# Changelog

All notable changes to hwtag are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and hwtag
follows [Semantic Versioning](https://semver.org/): the exported Go API of
`plugin` and `ykpiv` is covered by the v1 compatibility promise (see the
README). Each release lists the moves of the `go` directive, the toolchain and
the security-relevant dependencies, so that modules depending on hwtag can
move in step.

## [Unreleased]

## [1.2.0] - 2026-10-26

### Added
- `UnwrapInto(dst, stanzas)` on the p256tag identities (`plugin.TPMTagIdentity`,
  `ykpiv.Identity`), for callers that hold the file key in memory they manage:
  the key goes only to `dst` (checked to be 16 bytes before any PIN prompt),
  and hwtag's own copies are wiped. Copies inside go-tpm, piv-go, hpke and the
  Go runtime are out of reach.

### Changed
- Both p256tag unwrap paths wipe the ECDH shared secret once the HPKE context
  is set up, and the TPM path drops the shared point's Y coordinate.
- Pins unchanged since 1.1.0: `go 1.26.0`, toolchain go1.27.3,
  golang.org/x/crypto v0.58.0, golang.org/x/sys v0.49.0,
  github.com/google/go-tpm v0.9.8, github.com/google/go-tpm-tools v0.4.11,
  filippo.io/age v1.3.2.

### Fixed
- `age-plugin-ykpiv` could not decrypt a file encrypted to several p256tag
  recipients (such as a TPM and a YubiKey) unless the YubiKey's stanza came
  first: `ykpiv.Identity.Unwrap` gave up at the first stanza for another key
  instead of skipping it. Present since 1.1.0.

## [1.1.0] - 2026-10-21

The first hwtag release, forked from age-plugin-tpm v1.0.1.

### Added
- Windows support for `age-plugin-tpm` through the TPM Base Services (TBS).
- `age-plugin-ykpiv`: p256tag decryption with a YubiKey PIV key; PIN and
  touch policy always, attested at generation and checked at every use;
  `--setup` for a fresh key with PIN, PUK and a random management key.
- Fuzz tests for the identity, recipient and stanza parsers.

### Changed
- The TPM key is authorized with an HMAC session (PIN proven, not sent)
  instead of a password session.
- The TPM simulator and `AGE_TPM_PIN` exist only in test builds
  (`-tags agetpmsim`); a production binary refuses `AGE_TPM_PIN`.
- Identity parsing accepts only versions 1 and 2; p256tag and tpm-ecc stanza
  arguments are length-checked as in age's reference identity.
- Module path `github.com/deadpoets/hwtag`; toolchain pinned to go1.27.3
  (GO-2026-6809 in crypto/x509, reached by the YubiKey attestation check).
- Pins: `go 1.26.0`, toolchain go1.27.3, golang.org/x/crypto v0.58.0,
  golang.org/x/sys v0.49.0, github.com/google/go-tpm v0.9.8,
  github.com/google/go-tpm-tools v0.4.11, filippo.io/age v1.3.2.

### Fixed
- `--pin` with an empty PIN silently created a PIN-less key.
- A crafted version-0 identity made the plugin panic.
- A transient SRK was left loaded when its name did not match the identity.
- The TPM context was not closed before exit in plugin mode.
- `--log-file` was opened read-only and never logged.
- The PIN prompt's clear-line escape was written to stdin.

[Unreleased]: https://github.com/deadpoets/hwtag/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/deadpoets/hwtag/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/deadpoets/hwtag/releases/tag/v1.1.0
