#!/bin/sh
# usage: fetch-trivy.sh <amd64|arm64>
#
# Puts the Trivy that trivy.lock pins in dist-trivy/<arch>/casaos-trivy, for the release
# archive. The release is taken from GitHub over HTTPS and nothing of it is unpacked before
# its SHA-256 is the pinned one: a release replaced upstream (as v0.69.4 was a malicious
# one in March 2026, GHSA-69fq-xp46-6x23) stops the build here.
set -eu
cd "$(dirname "$0")/.."

lock=${TRIVY_LOCK:-trivy.lock}
arch=${1:?usage: fetch-trivy.sh <amd64|arm64>}
case $arch in
  amd64) asset_arch=64bit ;;
  arm64) asset_arch=ARM64 ;;
  *) echo "fetch-trivy: no Trivy is pinned for $arch" >&2; exit 1 ;;
esac

version=$(sed -n 's/^VERSION=//p' "$lock")
sum=$(sed -n "s/^SHA256_$arch=//p" "$lock")
case $version in ''|*[!0-9.]*) echo "fetch-trivy: $lock has no VERSION" >&2; exit 1 ;; esac
case $sum in *[!0-9a-f]*) sum= ;; esac
[ "${#sum}" -eq 64 ] || { echo "fetch-trivy: $lock has no SHA256_$arch" >&2; exit 1; }

asset=trivy_${version}_Linux-${asset_arch}.tar.gz
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL --retry 3 --proto '=https' -o "$work/$asset" "https://github.com/aquasecurity/trivy/releases/download/v$version/$asset"
echo "$sum  $work/$asset" | sha256sum -c - >/dev/null || { echo "fetch-trivy: $asset is not the pinned release (SHA-256 differs)" >&2; exit 1; }

# the one file that is shipped, whatever else the archive holds
tar -xzf "$work/$asset" -C "$work" trivy
mkdir -p "dist-trivy/$arch"
mv "$work/trivy" "dist-trivy/$arch/casaos-trivy"
chmod 0755 "dist-trivy/$arch/casaos-trivy"
