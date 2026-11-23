#!/bin/sh
# Proves fetch-trivy.sh: the pinned release is fetched, and a release whose SHA-256 is not the
# pinned one leaves nothing behind. Downloads about 50 MB.
set -eu
cd "$(dirname "$0")/.."

rm -rf dist-trivy
sh scripts/fetch-trivy.sh amd64
bin=dist-trivy/amd64/casaos-trivy
[ -s "$bin" ] || { echo "FAIL: $bin is not there"; exit 1; }
[ "$(head -c 4 "$bin" | od -An -c | tr -d ' ')" = '177ELF' ] || { echo "FAIL: $bin is not an ELF program"; exit 1; }
if [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ]; then
  "$bin" --version | grep -q "Version: $(sed -n 's/^VERSION=//p' trivy.lock)" || { echo "FAIL: not the pinned version"; exit 1; }
fi

rm -rf dist-trivy
tampered=$(mktemp)
trap 'rm -f "$tampered"' EXIT
sed 's/^SHA256_amd64=./SHA256_amd64=0/' trivy.lock > "$tampered"
if cmp -s trivy.lock "$tampered"; then echo "FAIL: the test did not change the sum"; exit 1; fi
if TRIVY_LOCK="$tampered" sh scripts/fetch-trivy.sh amd64 2>/dev/null; then echo "FAIL: a wrong SHA-256 is accepted"; exit 1; fi
if [ -n "$(find dist-trivy -type f 2>/dev/null)" ]; then echo "FAIL: a refused download left a file"; exit 1; fi

if sh scripts/fetch-trivy.sh riscv64 2>/dev/null; then echo "FAIL: an architecture with no pinned sum is accepted"; exit 1; fi

echo PASS
