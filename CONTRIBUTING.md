# Contributing to hwtag

Thanks for taking the time. hwtag is small and security-sensitive, so the
bar is "every change is understood, tested and reviewed", not "every change
is big".

## Before you start

- Open an issue first for anything beyond a small fix, so the design is
  agreed before the code exists. Bug reports and feature requests have
  templates.
- Security problems go to [SECURITY.md](SECURITY.md), never to a public issue.
- Changes to the identity or stanza formats are not accepted: people have
  files and hardware identities that must keep working. A new format needs a
  new version byte and a migration story, discussed in an issue first.

## How work gets in

1. Fork, branch from `main`, make the change.
2. `make check`, `make test` (needs a C compiler for the TPM simulator), and
   `make fuzz` if you touched a parser. CI runs the same plus cross-builds,
   staticcheck and govulncheck; a red check blocks the merge.
3. Open a pull request against `main` with the template filled in. Say
   what you tested on real hardware, if anything; the maintainer runs the
   TPM and YubiKey paths on hardware before anything is released.
4. Sign off each commit (`git commit -s`) to certify the
   [Developer Certificate of Origin](https://developercertificate.org/). CI
   checks for the `Signed-off-by` line.
5. Review: the maintainer reviews every pull request, and `main` only
   accepts pull requests that have that review, green checks and no open
   review threads. Force pushes and direct pushes are refused by the
   repository rules.

Keep pull requests to one topic. Rebase on `main` rather than merge from
it; `main` has a linear history.

## Style

- `gofmt`, `go vet` and staticcheck clean; the Go the file around you
  already uses.
- Comments say *why*, in full sentences. Upstream's code is kept in its
  style where it is unchanged, so pulling upstream fixes stays easy.
- No new dependencies without a reason in the pull request; the dependency
  set is deliberately small, and production binaries build with
  `CGO_ENABLED=0`.
- Never log, print or put in an error message a PIN, a PUK, a management
  key, a file key or a shared secret.

## Tools

Work produced with the help of language models or other tools is welcome
on the same terms as any other: you must understand what you submit, have
tested it, and stand behind it under the DCO. The review is of the change,
not of how it was written.

## Pulling from upstream

hwtag tracks [Foxboron/age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm)
one way. Upstream changes are cherry-picked into `plugin/` and
`cmd/age-plugin-tpm/` by the maintainer with the upstream author kept on the
commit. Please do not open issues or pull requests upstream on hwtag's
behalf.
