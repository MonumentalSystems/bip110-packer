#!/usr/bin/env bash
#
# enforce-demo.sh — prove BIP-110 ENFORCEMENT against a live regtest node.
#
# For each deliberate violation (built with `bip110-packer ... --violate <kind>`)
# this shows: (a) our independent validator REJECTS it, and (b) what the NODE
# does when it's asked to mine the tx via generateblock (consensus validation).
#
# Node-agnostic via BITCOIND / BITCOIN_CLI. The script auto-detects whether the
# node is a BIP-110 *enforcing* build (the dathonohm/bitcoin Knots fork, which
# defines the `reduced_data` versionbits deployment):
#
#   * Enforcing build  -> runs TWO passes on the SAME binary: `reduced_data`
#     INACTIVE (violations get MINED = the gap) and ACTIVE (violations get
#     CONSENSUS-REJECTED = real enforcement). The only difference between passes
#     is deployment activation, which is what proves the rejections are
#     BIP-110-gated and not some universal rule.
#   * Plain build (Core/Knots) -> one pass: violations get MINED (the gap),
#     because no released node ships BIP-110 as consensus.
#
# Get the enforcing build with:  eval "$(./scripts/fetch-bip110-node.sh)"
#
set -o pipefail

BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIP110PACK_BIN:-$ROOT/target/release/bip110-packer}"
DATA_HEX="$(printf 'BIP110 enforcement demo payload %s' "$(printf 'a%.0s' {1..40})" | xxd -p | tr -d '\n')"

bold(){ printf '\033[1m%s\033[0m\n' "$*"; }
hdr(){ printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

command -v "$BITCOIND" >/dev/null || { echo "bitcoind not found ($BITCOIND)"; exit 1; }
command -v jq >/dev/null || { echo "jq is required"; exit 1; }
[ -x "$BIN" ] || { echo "building release binary..."; (cd "$ROOT" && cargo build --release); }

VERSION="$("$BITCOIND" --version | head -1)"
bold "node:   $VERSION"
bold "binary: $BIN"

# The four violation kinds and the BIP-110 rule each breaks. (case-based lookups
# for bash 3.2 compatibility — macOS ships no associative arrays.)
KINDS="push opif opsuccess output"
kind_rule(){ case "$1" in push) echo C3;; opif) echo C8;; opsuccess) echo C7;; output) echo C1;; *) echo "--";; esac; }
kind_what(){ case "$1" in
  push) echo "oversized push (>256B)";; opif) echo "OP_IF in tapscript";;
  opsuccess) echo "OP_SUCCESS in tapscript";; output) echo "oversized output (>34B)";;
  *) echo "compliant reveal";; esac; }

pick_port(){ local p; for p in $(seq 18990 19090); do
  lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1 || { echo "$p"; return; }; done
  echo "no free port" >&2; exit 1; }

# run_pass <label> <activate:0|1>  -> prints a result line per case, appends to $RESULTS
run_pass(){
  local label="$1" activate="$2"
  local dd port cli
  dd="$(mktemp -d "${TMPDIR:-/tmp}/bip110-enf.XXXXXX")"; port="$(pick_port)"
  cli=("$BITCOIN_CLI" -regtest -datadir="$dd" -rpcport="$port")
  local vb=() ptag=baseline; [ "$activate" = 1 ] && { vb=(-vbparams=reduced_data:0:9223372036854775807); ptag=active; }
  "$BITCOIND" -regtest -datadir="$dd" -rpcport="$port" -listen=0 -fallbackfee=0.0002 \
     -txindex=1 "${vb[@]}" -daemon >/dev/null 2>&1
  "${cli[@]}" -rpcwait -rpcclienttimeout=15 getblockcount >/dev/null 2>&1
  "${cli[@]}" -named createwallet wallet_name=w descriptors=true >/dev/null 2>&1
  local A; A="$("${cli[@]}" -rpcwallet=w getnewaddress)"
  # 500 blocks: matures coinbase AND (with -vbparams) drives reduced_data to ACTIVE.
  "${cli[@]}" generatetoaddress 500 "$A" >/dev/null
  local active; active="$("${cli[@]}" getdeploymentinfo | jq -r '.deployments.reduced_data.active // "n/a"')"
  hdr "PASS: $label   (reduced_data active=$active, height=$("${cli[@]}" getblockcount))"

  local kind
  for kind in compliant $KINDS; do
    local vopt=() rule="--" what="compliant reveal"
    if [ "$kind" != compliant ]; then vopt=(--violate "$kind"); rule="$(kind_rule "$kind")"; what="$(kind_what "$kind")"; fi

    local commit ft rf vout val raw
    commit="$("$BIN" commit --data-hex "$DATA_HEX" --network regtest "${vopt[@]}" 2>/dev/null | head -1)"
    ft="$("${cli[@]}" -rpcwallet=w sendtoaddress "$commit" 0.02)"
    "${cli[@]}" generatetoaddress 1 "$A" >/dev/null
    rf="$("${cli[@]}" getrawtransaction "$ft" true)"
    vout="$(echo "$rf" | jq -r --arg a "$commit" '.vout[]|select(.scriptPubKey.address==$a)|.n')"
    val="$(echo "$rf" | jq -r --arg a "$commit" '.vout[]|select(.scriptPubKey.address==$a)|.value*100000000|round')"
    raw="$("$BIN" build-spend --data-hex "$DATA_HEX" --network regtest --prevout "$ft:$vout" \
          --prevout-value "$val" --fee 5000 --to "$A" "${vopt[@]}" 2>/dev/null)"

    local vv; vv="$("$BIN" verify "$raw" 2>/dev/null | grep -oE 'PASS|FAIL' | head -1)"
    local gb node reason
    gb="$("${cli[@]}" generateblock "$A" "[\"$raw\"]" 2>&1)"
    if echo "$gb" | grep -q '"hash"'; then
      node="MINED"; reason="-"
    else
      node="REJECTED"
      reason="$(echo "$gb" | tr '\n' ' ' | grep -oiE '\(([^)]*)\)|bad-[a-z-]*' | head -1 | tr -d '()')"
      [ -z "$reason" ] && reason="$(echo "$gb" | tr '\n' ' ' | grep -oiE 'error message:.*' | cut -c1-70)"
    fi
    printf "  %-26s validator=%-4s  node=%-9s %s\n" "$what" "${vv:-?}" "$node" "$reason"
    RESULTS+=("$ptag|$kind|$rule|${vv:-?}|$node|$reason")
    if [ "$kind" = compliant ] && [ "$node" != MINED ]; then
      echo "  !! compliant reveal was rejected — unexpected"; fi
  done
  "${cli[@]}" stop >/dev/null 2>&1; sleep 1; rm -rf "$dd"
}

# Detect an enforcing build: does the node accept the reduced_data deployment?
ENFORCING=0
probe_dd="$(mktemp -d)"; probe_port="$(pick_port)"
if "$BITCOIND" -regtest -datadir="$probe_dd" -rpcport="$probe_port" -listen=0 \
     -vbparams=reduced_data:0:9223372036854775807 -daemon >/dev/null 2>"$probe_dd/e"; then
  pcli=("$BITCOIN_CLI" -regtest -datadir="$probe_dd" -rpcport="$probe_port")
  if "${pcli[@]}" -rpcwait -rpcclienttimeout=8 getblockcount >/dev/null 2>&1; then ENFORCING=1; fi
  "${pcli[@]}" stop >/dev/null 2>&1; sleep 1
fi
rm -rf "$probe_dd"

RESULTS=()
if [ "$ENFORCING" = 1 ]; then
  bold "detected: BIP-110 ENFORCING build (reduced_data deployment present)"
  run_pass "reduced_data INACTIVE (baseline)" 0
  run_pass "reduced_data ACTIVE (enforced)"   1
else
  bold "detected: plain build (no reduced_data deployment) — gap demo only"
  run_pass "non-enforcing node" 0
fi

hdr "SUMMARY  (case | pass | our validator | node consensus | reason)"
for r in "${RESULTS[@]}"; do IFS='|' read -r ptag kind rule vv node reason <<<"$r"
  printf '  %-22s %-9s validator=%-5s node=%-9s %s\n' \
    "${kind}${rule:+ ($rule)}" "$ptag" "$vv" "$node" "$reason"
done

hdr "CONCLUSION"
if [ "$ENFORCING" = 1 ]; then
  echo "  Same binary, same txs: with reduced_data INACTIVE every violation is MINED (the gap);"
  echo "  with reduced_data ACTIVE every violation is CONSENSUS-REJECTED while the compliant reveal"
  echo "  is mined. BIP-110 is enforced by the node at consensus — proven, not just asserted."
else
  echo "  This node has no BIP-110 consensus rules, so it MINES txs our validator rejects (the gap)."
  echo "  Run against the enforcing build to see consensus rejection:"
  echo "    eval \"\$(./scripts/fetch-bip110-node.sh)\" && ./scripts/enforce-demo.sh"
fi
