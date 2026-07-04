#!/usr/bin/env bash
#
# channels-demo.sh — prove EVERY BIP-110 encoding channel end-to-end on a live
# regtest node: build the tx, mine it via generateblock (consensus validation),
# and recover the exact payload from the MINED transaction.
#
# Node-agnostic via BITCOIND / BITCOIN_CLI (defaults: bitcoind / bitcoin-cli).
# Also exercises the --compress DEFLATE pre-pass.
#
set -o pipefail

BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIP110PACK_BIN:-$ROOT/target/release/bip110-packer}"

command -v "$BITCOIND" >/dev/null || { echo "bitcoind not found ($BITCOIND)"; exit 1; }
command -v jq >/dev/null || { echo "jq required"; exit 1; }
[ -x "$BIN" ] || (cd "$ROOT" && cargo build --release)

pick_port(){ local p; for p in $(seq 18990 19090); do
  lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1 || { echo "$p"; return; }; done; exit 1; }
DD="$(mktemp -d "${TMPDIR:-/tmp}/bip110-chan.XXXXXX")"; P="$(pick_port)"
CLI=("$BITCOIN_CLI" -regtest -datadir="$DD" -rpcport="$P")
cleanup(){ "${CLI[@]}" stop >/dev/null 2>&1; sleep 1; rm -rf "$DD"; }
trap cleanup EXIT

"$BITCOIND" -regtest -datadir="$DD" -rpcport="$P" -listen=0 -fallbackfee=0.0002 -txindex=1 -daemon >/dev/null 2>&1
"${CLI[@]}" -rpcwait -rpcclienttimeout=15 getblockcount >/dev/null 2>&1
"${CLI[@]}" -named createwallet wallet_name=w descriptors=true >/dev/null
A="$("${CLI[@]}" -rpcwallet=w getnewaddress bech32)"
"${CLI[@]}" generatetoaddress 130 "$A" >/dev/null
printf '\033[1mnode: %s   height=%s\033[0m\n' "$("$BITCOIND" --version | head -1)" "$("${CLI[@]}" getblockcount)"

PAYLOAD="Pack me into a real regtest block — every BIP-110 channel, round-tripped. 0123456789"
HEX="$(printf '%s' "$PAYLOAD" | xxd -p | tr -d '\n')"

finish(){ # <ch> <label> <rawtx>
  local ch="$1" label="$2" raw="$3"
  local vv gb txid mined out sz
  vv="$("$BIN" verify "$raw" 2>/dev/null | grep -oE 'PASS|FAIL')"
  sz=$(( ${#raw} / 2 ))
  gb="$("${CLI[@]}" generateblock "$A" "[\"$raw\"]" 2>&1)"
  if ! echo "$gb" | grep -q '"hash"'; then
    printf "  %-24s validate=%-4s MINE-FAIL: %s\n" "$label" "$vv" \
      "$(echo "$gb" | tr '\n' ' ' | grep -oiE 'error message:.*' | cut -c1-60)"; return; fi
  txid="$("$BIN" verify "$raw" 2>/dev/null | awk '/^txid:/{print $2}')"
  mined="$("${CLI[@]}" getrawtransaction "$txid")"
  out="$("$BIN" extract "$mined" --channel "$ch" 2>/dev/null)"
  if [ "$out" = "$HEX" ]; then
    printf "  %-24s validate=%-4s MINED ✓ round-trip ✓ (tx %sB)\n" "$label" "$vv" "$sz"
  else
    printf "  %-24s validate=%-4s MINED ✓ round-trip ✗\n" "$label" "$vv"; fi
}

# commit/reveal channels: fund a commit address, then self-spend (anyone-can-spend reveal)
commit_reveal(){
  local ch="$1" extra="$2" commit ft rf vout val raw
  commit="$("$BIN" commit --data-hex "$HEX" --channel "$ch" $extra --network regtest 2>/dev/null | head -1)"
  ft="$("${CLI[@]}" -rpcwallet=w sendtoaddress "$commit" 0.02)"
  "${CLI[@]}" generatetoaddress 1 "$A" >/dev/null
  rf="$("${CLI[@]}" getrawtransaction "$ft" true)"
  vout="$(echo "$rf" | jq -r --arg a "$commit" '.vout[]|select(.scriptPubKey.address==$a)|.n')"
  val="$(echo "$rf" | jq -r --arg a "$commit" '.vout[]|select(.scriptPubKey.address==$a)|.value*1e8|round')"
  raw="$("$BIN" build-spend --data-hex "$HEX" --channel "$ch" $extra --network regtest \
        --prevout "$ft:$vout" --prevout-value "$val" --fee 5000 --to "$A" 2>/dev/null)"
  finish "$ch" "${ch}${extra:+ (compress)}" "$raw"
}

# output-only channels: spend a wallet UTXO (wallet signs the input)
output_only(){
  local ch="$1" u ft vout val raw signed
  u="$("${CLI[@]}" -rpcwallet=w listunspent 1 | jq -c '[.[]|select(.amount>0.5)][0]')"
  ft="$(echo "$u" | jq -r .txid)"; vout="$(echo "$u" | jq -r .vout)"; val="$(echo "$u" | jq -r '.amount*1e8|round')"
  raw="$("$BIN" build-spend --data-hex "$HEX" --channel "$ch" --network regtest \
        --prevout "$ft:$vout" --prevout-value "$val" --fee 5000 --to "$A" 2>/dev/null)"
  signed="$("${CLI[@]}" -rpcwallet=w signrawtransactionwithwallet "$raw" | jq -r .hex)"
  finish "$ch" "$ch" "$signed"
}

printf '\n\033[1;36m== commit/reveal channels (witness data)\033[0m\n'
commit_reveal tapleaf ""
commit_reveal control-block ""
commit_reveal witness-args ""
commit_reveal p2wsh-envelope ""
commit_reveal tapleaf "--compress"

printf '\n\033[1;36m== output-only channels (base bytes)\033[0m\n'
output_only op-return
output_only fake-key
output_only stego

printf '\n\033[1;36m== DONE — every channel mined into a block and round-tripped from it\033[0m\n'
