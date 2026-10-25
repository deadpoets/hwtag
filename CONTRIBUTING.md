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

## Releasing (maintainer)

Releases are cut only with the script, never by hand:

```
bash .github/scripts/release.sh --check v1.2.0   # every gate, nothing changed
bash .github/scripts/release.sh v1.2.0           # gates, two confirmations, tag, publish
```

A published version is permanent: the Go module proxy and checksum database
never forget it, and since v1.1.0 the exported API of `plugin` and `ykpiv` is
under the v1 compatibility promise. So the script refuses to tag unless the
checkout is a clean `main` equal to `origin/main`; the version is unused in
git and on proxy.golang.org; `gorelease` accepts it against the latest
published version (additions need a minor version, and incompatible changes
are refused outright); `go.mod`'s toolchain is the newest Go release and the
machine runs it; every CI check on the commit passed; the simulator tests
pass and every release target builds locally; and `CHANGELOG.md` has a
non-empty `## [X.Y.Z]` section, which becomes the release notes.

It then asks the person at the terminal to confirm, by typing the commit
hash, that this commit's binaries ran on a real TPM and a real YubiKey, and
once more before tagging. There is no switch to skip either question. It
creates a signed tag, verifies it, pushes it and publishes the GitHub Release,
which makes `build.yml` attach the binaries and their sha256 sums.

The order is: changelog PR (move `[Unreleased]` to `[X.Y.Z] - date`) →
merge → hardware run → `release.sh`. Because the script's own check asks the
proxy about the version first, the new version may take about 30 minutes to
resolve through proxy.golang.org.

## Pulling from upstream

hwtag tracks [Foxboron/age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm)
one way. Upstream changes are cherry-picked into `plugin/` and
`cmd/age-plugin-tpm/` by the maintainer with the upstream author kept on the
commit. Please do not open issues or pull requests upstream on hwtag's
behalf.
