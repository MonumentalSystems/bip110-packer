#!/usr/bin/env bash
#
# regtest-demo.sh — prove bip110-packer end-to-end against a live Bitcoin node.
#
# Spins up a throwaway regtest node, funds a Taproot commit address, builds the
# data-carrying reveal transaction with bip110-packer, mines it directly into a
# block (miner-inclusion path — the same path a miner uses, bypassing the
# non-standard-tx relay policy that would reject a big data tx over the P2P
# network), then proves:
#   1. our independent BIP-110 checker PASSES the reveal tx;
#   2. the node ACCEPTS the block (consensus-valid — generateblock rejects any
#      consensus-invalid tx);
#   3. the exact arbitrary bytes are recoverable from the mined witness.
#
# Runs both auth modes (anyone-can-spend and OP_CHECKSIG-authenticated).
#
# Node-agnostic: point it at Bitcoin Knots (the node shipping the stricter
# BIP-110 / datacarrier enforcement) by exporting BITCOIND / BITCOIN_CLI, e.g.
#   BITCOIND=/path/to/knots/bitcoind BITCOIN_CLI=/path/to/knots/bitcoin-cli ./scripts/regtest-demo.sh
#
set -euo pipefail

BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIP110PACK_BIN:-$ROOT/target/release/bip110-packer}"

# Pick a free RPC port (regtest P2P is disabled with -listen=0, so no P2P port).
pick_port() {
  local p
  for p in $(seq 18990 19090); do
    if ! lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then echo "$p"; return; fi
  done
  echo "no free RPC port in 18990-19090" >&2; exit 1
}
RPCPORT="$(pick_port)"
DATADIR="$(mktemp -d "${TMPDIR:-/tmp}/bip110-regtest.XXXXXX")"
CLI=("$BITCOIN_CLI" "-regtest" "-datadir=$DATADIR" "-rpcport=$RPCPORT" "-rpcwait")

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

cleanup() {
  "${CLI[@]}" stop >/dev/null 2>&1 || true
  sleep 1
  rm -rf "$DATADIR"
}
trap cleanup EXIT

# --- sanity ---
command -v "$BITCOIND" >/dev/null || { echo "bitcoind not found ($BITCOIND)"; exit 1; }
command -v jq >/dev/null || { echo "jq is required"; exit 1; }
[ -x "$BIN" ] || { echo "building release binary..."; (cd "$ROOT" && cargo build --release); }

bold "node:   $("$BITCOIND" --version | head -1)"
bold "binary: $BIN"
bold "datadir: $DATADIR"

step "Start regtest node"
"$BITCOIND" -regtest -datadir="$DATADIR" -rpcport="$RPCPORT" -listen=0 \
  -daemon -fallbackfee=0.0002 -txindex=1 -blockmintxfee=0 >/dev/null
"${CLI[@]}" createwallet demo >/dev/null
MINER="$("${CLI[@]}" -rpcwallet=demo getnewaddress)"
echo "miner address: $MINER"
"${CLI[@]}" generatetoaddress 101 "$MINER" >/dev/null
echo "mined 101 blocks (coinbase mature); balance: $("${CLI[@]}" -rpcwallet=demo getbalance) BTC"

# demo_run <auth> <payload-file>
demo_run() {
  local AUTH="$1" PAYLOAD="$2"
  local NBYTES; NBYTES=$(wc -c < "$PAYLOAD" | tr -d ' ')
  step "Reveal demo — auth=$AUTH, payload=$NBYTES bytes"

  # 1. commit address
  local COMMIT; COMMIT="$("$BIN" commit --input "$PAYLOAD" --auth "$AUTH" --network regtest 2>/dev/null | head -1)"
  echo "commit address: $COMMIT"

  # 2. fund it and confirm
  local FUND_TXID; FUND_TXID="$("${CLI[@]}" -rpcwallet=demo sendtoaddress "$COMMIT" 0.02)"
  "${CLI[@]}" generatetoaddress 1 "$MINER" >/dev/null
  local RAWFUND; RAWFUND="$("${CLI[@]}" getrawtransaction "$FUND_TXID" true)"
  local VOUT VALSAT
  VOUT=$(echo "$RAWFUND" | jq -r --arg a "$COMMIT" '.vout[] | select(.scriptPubKey.address==$a) | .n')
  VALSAT=$(echo "$RAWFUND" | jq -r --arg a "$COMMIT" '.vout[] | select(.scriptPubKey.address==$a) | .value * 100000000 | round')
  echo "funded: $FUND_TXID:$VOUT  value=$VALSAT sat (confirmed)"

  # 3. build the signed reveal tx
  local REVEAL; REVEAL="$("$BIN" build-spend --input "$PAYLOAD" --auth "$AUTH" --network regtest \
    --prevout "$FUND_TXID:$VOUT" --prevout-value "$VALSAT" --fee 5000 --to "$MINER" 2>/tmp/bs.err)"
  sed 's/^/    /' /tmp/bs.err

  # 4. independent BIP-110 check
  echo "--- bip110-packer verify (independent checker) ---"
  "$BIN" verify "$REVEAL" | sed 's/^/    /'

  # 5. policy vs consensus: relay would reject (non-standard), miner inclusion accepts
  echo "--- testmempoolaccept (relay policy) ---"
  "${CLI[@]}" testmempoolaccept "[\"$REVEAL\"]" \
    | jq -r '.[0] | "    allowed=\(.allowed) reject-reason=\(.["reject-reason"] // "none")"'

  # 6. mine it directly into a block (consensus validation happens here)
  echo "--- generateblock (miner inclusion; consensus-validated) ---"
  local GB BLOCKHASH REVEAL_TXID
  GB="$("${CLI[@]}" generateblock "$MINER" "[\"$REVEAL\"]")"
  BLOCKHASH=$(echo "$GB" | jq -r '.hash')
  REVEAL_TXID=$("$BIN" verify "$REVEAL" 2>/dev/null | awk '/^txid:/{print $2}')
  local BLOCK; BLOCK="$("${CLI[@]}" getblock "$BLOCKHASH" 2)"
  local INBLOCK; INBLOCK=$(echo "$BLOCK" | jq -r --arg t "$REVEAL_TXID" '[.tx[].txid] | index($t) != null')
  echo "    block:        $BLOCKHASH (height $(echo "$BLOCK" | jq -r .height))"
  echo "    block weight: $(echo "$BLOCK" | jq -r .weight) WU"
  echo "    reveal txid:  $REVEAL_TXID"
  echo "    in block:     $INBLOCK"
  [ "$INBLOCK" = "true" ] || { echo "FAIL: reveal tx not in block"; exit 1; }

  # 7. recover the exact bytes from the mined witness
  local MINEDHEX RECOVERED
  MINEDHEX="$("${CLI[@]}" getrawtransaction "$REVEAL_TXID")"
  "$BIN" extract "$MINEDHEX" --out /tmp/recovered.bin 2>/dev/null
  if cmp -s "$PAYLOAD" /tmp/recovered.bin; then
    echo "    round-trip:   OK — $NBYTES bytes recovered from the mined block match the input"
  else
    echo "FAIL: recovered bytes differ from input"; exit 1
  fi
}

# --- payloads ---
PAYLOAD_TXT="$DATADIR/payload.txt"
{
  echo "BIP-110-compliant arbitrary data, embedded in a Taproot script-path witness."
  echo "No OP_IF (banned in tapscript). No push > 256 bytes. Output <= 34 bytes."
  head -c 1800 /dev/urandom | xxd -p
} > "$PAYLOAD_TXT"

demo_run none "$PAYLOAD_TXT"
demo_run checksig "$PAYLOAD_TXT"

# --- headline max-pack figure (weight-accounting only; not broadcast) ---
step "Max block-fill projection (bip110-packer pack)"
head -c 4200000 /dev/urandom > "$DATADIR/big.bin"
"$BIN" pack --input "$DATADIR/big.bin" --out /dev/null 2>&1 | sed 's/^/    /'

step "DONE — all reveals mined and round-tripped; block accepted by $("$BITCOIND" --version | head -1)"
