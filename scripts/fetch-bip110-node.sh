#!/usr/bin/env bash
#
# fetch-bip110-node.sh — download the BIP-110 ENFORCING node (a Bitcoin Knots
# fork that adds the `reduced_data` deployment + BIP-110 consensus rules) and
# print the env vars to run the demos against it.
#
#   eval "$(./scripts/fetch-bip110-node.sh)"   # downloads + exports BITCOIND/BITCOIN_CLI
#   ./scripts/enforce-demo.sh                  # violations are now CONSENSUS-REJECTED
#   ./scripts/regtest-demo.sh                  # compliant data still mines
#
# Source: https://github.com/dathonohm/bitcoin  (see https://bip110.org).
# Override with BIP110_VERSION (e.g. 29.3.knots20260210+bip110-v0.4.1).
#
set -euo pipefail

BIP110_VERSION="${BIP110_VERSION:-29.3.knots20260210+bip110-v0.4.1}"
DEST="${BIP110_DEST:-$HOME/opt}"

os="$(uname -s)"; arch="$(uname -m)"
case "$os/$arch" in
  Darwin/arm64)  triplet="arm64-apple-darwin" ;;
  Darwin/x86_64) triplet="x86_64-apple-darwin" ;;
  Linux/x86_64)  triplet="x86_64-linux-gnu" ;;
  Linux/aarch64) triplet="aarch64-linux-gnu" ;;
  *) echo "unsupported platform: $os/$arch — see https://github.com/dathonohm/bitcoin/releases" >&2; exit 1 ;;
esac

tarball="bitcoin-${BIP110_VERSION}-${triplet}.tar.gz"
# GitHub URL-encodes the '+' in the tag/path as %2B.
enc_tag="v${BIP110_VERSION//+/%2B}"
enc_file="${tarball//+/%2B}"
url="https://github.com/dathonohm/bitcoin/releases/download/${enc_tag}/${enc_file}"
kroot="$DEST/bitcoin-${BIP110_VERSION}"

if [ ! -x "$kroot/bin/bitcoind" ]; then
  echo "downloading $url ..." >&2
  mkdir -p "$DEST"
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/$tarball" "$url"
  tar -xzf "$tmp/$tarball" -C "$DEST"
  rm -rf "$tmp"
fi

"$kroot/bin/bitcoind" --version | head -1 >&2
echo "export BITCOIND='$kroot/bin/bitcoind'"
echo "export BITCOIN_CLI='$kroot/bin/bitcoin-cli'"
