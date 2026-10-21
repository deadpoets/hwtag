# Security policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability
reporting on this repository ("Report a vulnerability" under the Security
tab), which reaches the maintainer only. You will get an acknowledgement
within a week and a fix or a reasoned answer within 90 days; credit is given
in the release notes unless you ask otherwise.

Things that are in scope: anything that lets a file be decrypted without
the hardware and its PIN or touch, that leaks a PIN or key material, that
weakens the session encryption to the TPM, or that lets a malformed input
crash or mislead the plugin.

## Supported versions

Only the latest release is supported. There is no backporting.

## What the plugins do not defend against

- A process running as the same user on the same machine: it can talk to
  the TPM or the card itself, and can read this process's memory.
- Loss of the hardware or of the identity file (TPM) with no backup; there
  is no recovery.
- A TPM or YubiKey firmware bug.

See the "Security notes" section of the README for what is checked and how.
