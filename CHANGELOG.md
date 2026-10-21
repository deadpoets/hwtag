# Changelog

## Unreleased: hwtag, from age-plugin-tpm v1.0.1

Added
- Windows support for `age-plugin-tpm` through the TPM Base Services (TBS).
- `age-plugin-ykpiv`: p256tag decryption with a YubiKey PIV key; PIN and
  touch policy always, attested at generation and checked at every use;
  `--setup` for a fresh key with PIN, PUK and a random management key.
- Fuzz tests for the identity, recipient and stanza parsers.

Changed
- The TPM key is authorized with an HMAC session (PIN proven, not sent)
  instead of a password session.
- The TPM simulator and `AGE_TPM_PIN` exist only in test builds
  (`-tags agetpmsim`); a production binary refuses `AGE_TPM_PIN`.
- Identity parsing accepts only versions 1 and 2; p256tag and tpm-ecc stanza
  arguments are length-checked as in age's reference identity.
- Module path `github.com/deadpoets/hwtag`; toolchain pinned to go1.27.3
  (GO-2026-6809 in crypto/x509, reached by the YubiKey attestation check).

Fixed
- `--pin` with an empty PIN silently created a PIN-less key.
- A crafted version-0 identity made the plugin panic.
- A transient SRK was left loaded when its name did not match the identity.
- The TPM context was not closed before exit in plugin mode.
- `--log-file` was opened read-only and never logged.
- The PIN prompt's clear-line escape was written to stdin.
