#!/usr/bin/env bash
# Build only: never creates/pushes tags or publishes assets.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:?usage: scripts/ouihelp-release-candidate.sh /absolute/artifact-directory}"
[[ "$out" = /* ]] || { echo 'Artifact directory must be absolute' >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo 'Refusing dirty source tree' >&2; exit 1; }
version=1.102.4-ouihelp.1
export TS_USE_TOOLCHAIN=1 TS_VERSION_OVERRIDE=1.102.4
export CGO_ENABLED=0
commit=$(git rev-parse HEAD)
git merge-base --is-ancestor v1.102.4 HEAD
mkdir -p "$out"
eval "$(./build_dist.sh shellvars)"
[[ "$VERSION_SHORT" = 1.102.4 && "$VERSION_GIT_HASH" = "$commit" ]]
{
  echo "Release: v$version"
  echo "Source: $commit"
  echo "Upstream: $(git rev-parse v1.102.4^{commit})"
  echo "Short: $VERSION_SHORT"
  echo "Long: $VERSION_LONG"
  echo "Toolchain revision: $(<go.toolchain.rev)"
  ./tool/go version
  echo 'Build: TS_USE_TOOLCHAIN=1 TS_VERSION_OVERRIDE=1.102.4 CGO_ENABLED=0 GOOS=linux GOARCH=<arch> ./build_dist.sh -o <output> ./cmd/<binary>'
} > "$out/BUILD-METADATA.txt"
for arch in amd64 arm64; do
  pkg="tailscale-$version-linux-$arch"
  mkdir -p "$out/$pkg"
  for bin in tailscale tailscaled; do
    GOOS=linux GOARCH="$arch" ./build_dist.sh -o "$out/$pkg/$bin" "./cmd/$bin"
    ./tool/go version -m "$out/$pkg/$bin" > "$out/$pkg/$bin.buildinfo.txt"
    grep -q "GOARCH=$arch" "$out/$pkg/$bin.buildinfo.txt"
    grep -q "vcs.revision=$commit" "$out/$pkg/$bin.buildinfo.txt"
    grep -q 'vcs.modified=false' "$out/$pkg/$bin.buildinfo.txt"
  done
  cp "$out/BUILD-METADATA.txt" "$out/$pkg/README.txt"
  tar --sort=name --mtime="@$(git show -s --format=%ct HEAD)" --owner=0 --group=0 --numeric-owner -C "$out" -cf - "$pkg" | gzip -n > "$out/$pkg.tar.gz"
done
"$out/tailscale-$version-linux-amd64/tailscale" version > "$out/VERSION-amd64.txt"
"$out/tailscale-$version-linux-amd64/tailscaled" --version >> "$out/VERSION-amd64.txt"
grep -q "^$VERSION_SHORT" "$out/VERSION-amd64.txt"
(cd "$out"; sha256sum tailscale-*/tailscale tailscale-*/tailscaled > BINARY-SHA256SUMS; sha256sum *.tar.gz BUILD-METADATA.txt BINARY-SHA256SUMS VERSION-amd64.txt > SHA256SUMS)
echo "Candidate ready in $out (not published)"
