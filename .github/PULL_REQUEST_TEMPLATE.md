## What and why

<!-- One topic per pull request. Link the issue this came from. -->

## Checks

- [ ] `make check` and `make test` pass locally (and `make fuzz` if a parser changed)
- [ ] No change to the identity or stanza formats (or: discussed in issue #…)
- [ ] No PIN, key or secret can reach a log, an error message or stdout
- [ ] Commits are signed off (`git commit -s`, DCO)
- [ ] Tested on hardware: <!-- which TPM / YubiKey and OS, or "not tested on hardware" -->
