#!/usr/bin/env bash
# Tag and publish an hwtag release, refusing to do it wrong.
#
# usage: release.sh [--check] <version>
#   release.sh --check v1.2.0   run every gate, change nothing, stop before any prompt
#   release.sh v1.2.0           run every gate, then ask, tag, push and publish
#
# Run it from anywhere in a checkout of main. Nothing is tagged or pushed until
# every gate below has passed and a human at a terminal has confirmed twice:
# once that this exact commit has been run on real hardware, once to tag.
#
# # Why this exists
#
# A release is permanent in a way nothing else in this repository is. The Go
# module proxy and the checksum database are append-only: once proxy.golang.org
# has served github.com/deadpoets/hwtag@vX.Y.Z, that version's content is fixed
# forever and can only be superseded, never repaired. And since v1.1.0 the
# exported API of plugin and ykpiv is under the v1 compatibility promise, so a
# release that breaks it breaks every importer silently. A checklist does not
# stop either mistake, because both look like success at the keyboard. These
# checks do.
#
# Adapted from secmem's .github/scripts/release.sh: one module instead of
# several, so no tag prefixes and no in-repo dependency ordering; an API
# compatibility check that fails rather than reports, because hwtag is already
# v1; and a hardware confirmation, because the README promises that every
# release's binaries ran on a real TPM and YubiKey before the tag.
set -euo pipefail

die() { printf '\n  REFUSING: %s\n\n' "$1" >&2; exit 1; }
ok()  { printf '  ok    %s\n' "$1"; }

check_only=0
if [ "${1:-}" = "--check" ]; then
  check_only=1
  shift
fi
[ $# -eq 1 ] || die "usage: release.sh [--check] <version>   e.g. release.sh --check v1.2.0"
version="$1"
tag="$version"

case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "version must look like v1.2.3 (or v1.2.3-rc.1), got: $version" ;;
esac

cd "$(git rev-parse --show-toplevel)"
module=$(go list -m)
[ "$module" = "github.com/deadpoets/hwtag" ] || die "this is $module, not github.com/deadpoets/hwtag"

# gorelease has no releases of its own; pin the commit so the gate that
# decides whether a version is compatible does not change underneath us. Move
# it deliberately, like any other pin.
GORELEASE=golang.org/x/exp/cmd/gorelease@v0.0.0-20261014143641-f0251eb4aa3e

printf '\nreleasing %s as %s\n\n' "$module" "$tag"

# ---------------------------------------------------------------------------
# The checkout. Tags come off exactly what origin/main has.
# ---------------------------------------------------------------------------

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "main" ] || die "on branch '$branch', not main. Tags come off main."
ok "on main"

[ -z "$(git status --porcelain)" ] || die "working tree is dirty. Commit or stash first."
ok "working tree clean"

git fetch --quiet origin main
[ "$(git rev-list --count origin/main..HEAD)" = "0" ] || die "local main has commits origin/main does not. Push first."
[ "$(git rev-list --count HEAD..origin/main)" = "0" ] || die "origin/main is ahead. Run: git pull --ff-only"
ok "main matches origin/main"
sha=$(git rev-parse HEAD)
short=$(git rev-parse --short=12 HEAD)

git rev-parse -q --verify "refs/tags/$tag" >/dev/null && die "tag $tag already exists locally. Pick the next version."
git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1 && die "tag $tag already exists on origin. Pick the next version."
ok "tag $tag is free in git"

# ---------------------------------------------------------------------------
# The proxy. Fail closed whenever it cannot be asked.
# ---------------------------------------------------------------------------

# http_code prints the status proxy.golang.org answered $1 with, or 000 when
# curl could not get an answer. The fallback stays outside the substitution;
# inside it, it would be appended to the 000 curl already printed.
http_code() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' "$1") || code="000"
  printf '%s' "${code:-000}"
}

# Asking the proxy about a version before it exists makes the proxy cache the
# 404 for a while, which is why a fresh tag resolves only after a delay (see the
# note at the end). That cost is worth paying: this is the check that stops a
# second, different vX.Y.Z from being cut after the first was fetched.
code=$(http_code "https://proxy.golang.org/${module}/@v/${version}.info")
case "$code" in
  404|410) ok "$version is unpublished on proxy.golang.org" ;;
  200)     die "$module@$version is ALREADY PUBLISHED on proxy.golang.org.
             The proxy and sum.golang.org are append-only; pick the next version." ;;
  000)     die "could not reach proxy.golang.org to check whether $version is taken.
             Re-run when you have network; publishing blind is how a version
             gets burned." ;;
  *)       die "proxy.golang.org returned HTTP $code for $version; not proceeding." ;;
esac

# The base for the compatibility check is the newest version the proxy serves,
# not the newest tag in git: this repository also carries upstream
# age-plugin-tpm's tags (v1.0.1 and earlier), which belong to another module
# path and were never published under this one.
latestbody=$(curl -s -w '
%{http_code}' "https://proxy.golang.org/${module}/@latest") || latestbody=$'\n000'
latestcode=$(printf '%s' "$latestbody" | tail -1)
base=$(printf '%s' "$latestbody" | sed '$d' | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("Version", ""))
except Exception:
    print("")' 2>/dev/null || true)
[ "$latestcode" = "200" ] && [ -n "$base" ] ||
  die "cannot determine the latest published $module (HTTP $latestcode).
             The compatibility check needs it and is not skipped because the
             proxy is unreachable."
ok "latest published version is $base"

python3 -c 'import re, sys
def parse(v):
    m = re.match(r"^v(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in m.groups()) if m else None
a, b = parse(sys.argv[1]), parse(sys.argv[2])
sys.exit(0 if (a and b and a > b) else 1)' "$version" "$base" ||
  die "$version is not newer than the published $base."
ok "$version is newer than $base"

# ---------------------------------------------------------------------------
# The API. hwtag is v1: a minor release may only add, a patch release may not
# even add. gorelease knows both rules; -version makes it a verdict on this
# exact number instead of a suggestion.
# ---------------------------------------------------------------------------

printf '  ...   gorelease -base=%s -version=%s\n' "$base" "$version"
report=$(mktemp)
notes=$(mktemp)
trap 'rm -f "$report" "$notes"' EXIT
if ! go run "$GORELEASE" -base="$base" -version="$version" >"$report" 2>&1; then
  cat "$report" >&2
  die "gorelease does not accept $version against $base (above).
             An incompatible change needs a deprecation instead, and an addition
             needs a minor version, not a patch."
fi
ok "gorelease accepts $version against $base"

# ---------------------------------------------------------------------------
# The toolchain. Go security fixes ship as patch releases, and go.mod's
# toolchain line is the one pin every build (CI, release workflow, this
# machine) takes its Go from.
# ---------------------------------------------------------------------------

pin=$(sed -nE 's/^toolchain go([0-9.]+)$/\1/p' go.mod)
floor=$(sed -nE 's/^go ([0-9.]+)$/\1/p' go.mod)
[ -n "$pin" ] && [ -n "$floor" ] || die "cannot read the go and toolchain lines from go.mod"
json=$(curl -fsS --retry 3 'https://go.dev/dl/?mode=json') ||
  die "cannot reach go.dev to check that go$pin is current."
releases=$(printf '%s\n' "$json" | sed -nE 's/^ *"version": "go([0-9.]+)",?$/\1/p' | awk '!seen[$0]++')
newest=$(printf '%s\n' "$releases" | sed -n 1p)
oldstable=$(printf '%s\n' "$releases" | sed -n 2p)
[ -n "$newest" ] && [ -n "$oldstable" ] || die "could not parse the release list from go.dev"
[ "$pin" = "$newest" ] || die "go.mod pins go$pin, but go$newest is out. Move the pin in its own PR first."
ok "toolchain go$pin is the newest release"
minor() { printf '%s' "$1" | cut -d. -f1,2; }
[ "$(minor "$floor")" = "$(minor "$oldstable")" ] ||
  die "go.mod's go directive is $floor; the supported floor is the oldstable minor $(minor "$oldstable")."
ok "go directive $floor is the oldstable minor"
got=$(go env GOVERSION)
[ "$got" = "go$pin" ] || die "this machine runs $got, not the pinned go$pin (GOTOOLCHAIN=$(go env GOTOOLCHAIN))."
ok "this machine runs go$pin"

# ---------------------------------------------------------------------------
# CI on this exact commit. Every check run must have finished and passed.
# ---------------------------------------------------------------------------

command -v gh >/dev/null 2>&1 || die "gh is not installed; it is needed to read CI and publish the release."
runs=$(gh api "repos/deadpoets/hwtag/commits/$sha/check-runs?per_page=100" \
  --jq '.check_runs[] | "\(.status) \(.conclusion) \(.name)"') ||
  die "could not read the check runs for $short from GitHub."
[ -n "$runs" ] || die "no CI check runs exist for $short. Wait for CI, or push it."
bad=$(printf '%s\n' "$runs" | grep -vE '^completed (success|skipped|neutral) ' || true)
[ -z "$bad" ] || die "CI on $short is not green:
$(printf '%s\n' "$bad" | sed 's/^/             /')"
ok "CI is green on $short ($(printf '%s\n' "$runs" | wc -l | tr -d ' ') check runs)"

# ---------------------------------------------------------------------------
# Local build and tests. CI runs on Linux; the release is cut on the
# maintainer's machine, so this is also the Windows run of the same commit.
# ---------------------------------------------------------------------------

printf '  ...   tests with the TPM simulator and the race detector\n'
CGO_ENABLED=1 go test -race -tags agetpmsim -count=1 ./... >"$report" 2>&1 || {
  grep -vE 'warning:|note:|^ +\||^ +[0-9]+ \||In file included|^ +from ' "$report" >&2
  die "go test with the simulator failed (above)."
}
CGO_ENABLED=0 go test -count=1 ./plugin >"$report" 2>&1 || { cat "$report" >&2; die "go test without cgo failed."; }
ok "tests pass"

printf '  ...   building every release target\n'
for target in windows/amd64 windows/arm64 linux/amd64 linux/arm64; do
  cmds="./cmd/age-plugin-tpm"
  case "$target" in windows/*) cmds="$cmds ./cmd/age-plugin-ykpiv" ;; esac
  for c in $cmds; do
    GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 \
      go build -trimpath -buildvcs=false -o /dev/null "$c" ||
      die "release build failed for $c on $target"
  done
done
ok "release targets build with CGO_ENABLED=0"

# ---------------------------------------------------------------------------
# The changelog. Keep a Changelog numbers the version bare: tag v1.2.0 is
# "## [1.2.0]". The section becomes the GitHub Release notes.
# ---------------------------------------------------------------------------

key="${version#v}"
# Written by Python with an explicit encoding, not printed: on Windows Python's
# stdout is cp1252 and the changelog is UTF-8.
set +e
python3 - "$key" "$notes" <<'PY'
import re, sys
key, out = sys.argv[1], sys.argv[2]
text = open('CHANGELOG.md', encoding='utf-8').read()
start = re.search(r'^## \[' + re.escape(key) + r'\][^\n]*\n', text, re.M)
if not start:
    sys.exit(3)
body = text[start.end():]
nxt = re.search(r'^## ', body, re.M)
section = (body[:nxt.start()] if nxt else body).strip()
if not section:
    sys.exit(4)
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    f.write(section + '\n')
PY
extract=$?
set -e
case "$extract" in
  0) ;;
  3) die "CHANGELOG.md has no '## [${key}]' entry. Cut the changelog in a PR, merge it, then release." ;;
  4) die "the '## [${key}]' section of CHANGELOG.md is empty." ;;
  *) die "failed to read CHANGELOG.md (python exit ${extract})" ;;
esac
ok "CHANGELOG.md has an entry for [$key] ($(wc -l <"$notes" | tr -d ' ') lines)"

printf '\n  all gates passed\n\n'
printf '  tag     %s\n' "$tag"
printf '  commit  %s\n' "$(git log --format='%h %s' -1)"
printf '  base    %s\n\n' "$base"

if [ "$check_only" -eq 1 ]; then
  printf '  --check: stopping here; nothing was tagged or pushed.\n\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# The human gates. There is deliberately no environment variable that skips
# them: the hardware run cannot be checked by a script, and a release with
# nobody at the keyboard is not one this repository makes.
# ---------------------------------------------------------------------------

if ! { : </dev/tty; } 2>/dev/null; then
  die "no terminal to confirm on. Run this yourself at a terminal (--check runs the gates without one)."
fi

cat >/dev/tty <<EOF

  Hardware. The README promises that each release's binaries ran on real
  hardware before the tag. Built from commit $short with
    CGO_ENABLED=0 go build -trimpath -buildvcs=false ./cmd/...
  confirm that you have, on this commit:
    - created and decrypted with an age-plugin-tpm identity on a real TPM
      (with and without a PIN), and
    - decrypted with an age-plugin-ykpiv identity on a real YubiKey.
  If anything was skipped, say so in the changelog before releasing.

EOF
read -r -p "  type the commit ($short) to confirm the hardware run: " reply </dev/tty
[ "$reply" = "$short" ] || { printf '\n  not confirmed; nothing changed\n\n'; exit 0; }

read -r -p "  create and push tag $tag? [y/N] " reply </dev/tty
case "$reply" in
  [yY]) ;;
  *) printf '\n  aborted, nothing changed\n\n'; exit 0 ;;
esac

# Signed and annotated, like v1.1.0. -s rather than -a, so the signature does
# not depend on tag.gpgSign being set.
git tag -s "$tag" -F - <<EOF || die "could not create the signed tag $tag; nothing was created or pushed.
             Check the signing setup: git config gpg.format / user.signingkey."
hwtag $version

See CHANGELOG.md under [$key].
EOF

# Take the tag back if it does not verify, so a signing problem does not leave
# a local tag that blocks every later run at the "already exists" gate.
if ! verify=$(git tag -v "$tag" 2>&1); then
  printf '%s\n' "$verify" >&2
  if git tag -d "$tag" >/dev/null; then
    die "tag $tag did not verify after creation; deleted it again, nothing pushed.
             Check the signing setup (gpg.format, user.signingkey, and for SSH
             signing gpg.ssh.allowedSignersFile) and re-run."
  fi
  die "tag $tag did not verify after creation AND could not be deleted.
             Remove it by hand (git tag -d $tag) before re-running. Nothing pushed."
fi
ok "tag created and signature verifies"

git push origin "$tag"
ok "tag pushed"

# The GitHub Release comes after the push and does not fail the script: the
# tag is the Go release and is already public. It matters more here than for a
# library, though: publishing the release is what makes build.yml attach the
# binaries and their sha256 sums. A pre-release is marked as one and never
# takes the Latest badge.
release_flags=(--latest)
case "$version" in *-*) release_flags=(--prerelease --latest=false) ;; esac
if gh release create "$tag" --title "hwtag $version" --notes-file "$notes" "${release_flags[@]}" >/dev/null 2>&1; then
  ok "GitHub Release created from the changelog; build.yml will attach the binaries"
else
  printf '  warn  could not create the GitHub Release (the tag IS published).\n'
  printf '        Without it there are no release binaries. Retry with:\n'
  printf '          gh release create %s --title "hwtag %s" --notes-file <(the [%s] section of CHANGELOG.md)\n' "$tag" "$version" "$key"
fi

printf '\n  published %s\n' "$tag"
printf '  Check that the release workflow attached the binaries and sha256 sums.\n'
printf '  proxy.golang.org cached the 404 from the gate above, so %s may not\n' "$version"
printf '  resolve for about 30 minutes. Check with:\n'
printf '    GOPROXY=proxy.golang.org go list -m %s@%s\n\n' "$module" "$version"
