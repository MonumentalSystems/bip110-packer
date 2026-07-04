#!/usr/bin/env bash
#
# fetch-knots.sh — download the official Bitcoin Knots binaries for this host and
# print the env vars needed to run the regtest demo against them.
#
# Knots is the node shipping the stricter datacarrier / BIP-110-style relay
# policy, so it's the most interesting node to prove against. Usage:
#
#   eval "$(./scripts/fetch-knots.sh)"        # downloads + exports BITCOIND/BITCOIN_CLI
#   ./scripts/regtest-demo.sh                 # now runs against Knots
#
# Override the version with KNOTS_VERSION (e.g. KNOTS_VERSION=29.3.knots20260508).
#
set -euo pipefail

KNOTS_VERSION="${KNOTS_VERSION:-29.3.knots20260508}"
DEST="${KNOTS_DEST:-$HOME/opt}"

# Map uname to Knots' release triplet.
os="$(uname -s)"; arch="$(uname -m)"
case "$os/$arch" in
  Darwin/arm64)  triplet="arm64-apple-darwin" ;;
  Darwin/x86_64) triplet="x86_64-apple-darwin" ;;
  Linux/x86_64)  triplet="x86_64-linux-gnu" ;;
  Linux/aarch64) triplet="aarch64-linux-gnu" ;;
  *) echo "unsupported platform: $os/$arch — download manually from https://bitcoinknots.org/" >&2; exit 1 ;;
esac

major="${KNOTS_VERSION%%.*}"
tarball="bitcoin-${KNOTS_VERSION}-${triplet}.tar.gz"
url="https://bitcoinknots.org/files/${major}.x/${KNOTS_VERSION}/${tarball}"
kroot="$DEST/bitcoin-${KNOTS_VERSION}"

if [ ! -x "$kroot/bin/bitcoind" ]; then
  echo "downloading $url ..." >&2
  mkdir -p "$DEST"
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/$tarball" "$url"
  tar -xzf "$tmp/$tarball" -C "$DEST"
  rm -rf "$tmp"
fi

"$kroot/bin/bitcoind" --version | head -1 >&2

# Emit shell-eval'able exports.
echo "export BITCOIND='$kroot/bin/bitcoind'"
echo "export BITCOIN_CLI='$kroot/bin/bitcoin-cli'"
