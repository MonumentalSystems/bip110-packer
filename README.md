# bip110pack

Maximally pack a Bitcoin block with **BIP-110-compliant arbitrary data**, and
prove it end-to-end against a live regtest node.

> **BIP-110** ("Reduced Data Temporary Softfork", draft, Dec 2025) *restricts*
> arbitrary data on Bitcoin. This tool does the opposite of what BIP-110 wants —
> it packs the **maximum** arbitrary data into a block while staying **fully
> compliant** with every one of BIP-110's limits. It's a demonstration that the
> soft fork constrains *how* data is embedded, not *whether* it can be.

Built on [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin) 0.32.

---

## The idea in one picture

BIP-110's binding limits are: outputs ≤ 34 bytes, every data push ≤ 256 bytes,
control blocks ≤ 257 bytes, no Taproot annex, and — inside tapscript — no
`OP_IF`/`OP_NOTIF` and no `OP_SUCCESS*`. Everything else about tapscript is wide
open: BIP342 removed the 10,000-byte script-size cap and the 201-opcode cap, and
the tapleaf script is *exempt* from the 256-byte witness-item limit.

So the densest legal vehicle is a **Taproot (v1) script-path spend** whose
tapleaf is a long, stack-neutral run of `push → drop`:

```
              ┌─ ord-compatible, depth-neutral data envelope ─┐
<pubkey> OP_CHECKSIG  "ord"  <chunk0> <chunk1> OP_2DROP  <chunk2> <chunk3> OP_2DROP … OP_DROP
└── auth (optional) ──┘      └ ≤255-byte pushes, each balanced away so the stack never grows ┘
```

* **Witness discount** — witness bytes cost 1 WU/byte (4× cheaper than base
  bytes), so a single tapleaf can approach the whole 4 MWU block.
* **No `OP_IF`** — the Ordinals `OP_FALSE OP_IF … OP_ENDIF` envelope is *illegal*
  in tapscript under BIP-110. `push`/`OP_2DROP` uses no conditionals.
* **No altstack stuffing** — `OP_TOALTSTACK` would blow the 1000-element combined
  stack cap. Push-then-drop keeps the stack depth ≈ 2 forever.
* **256-byte push cap** — we chunk at **255 bytes** (`OP_PUSHDATA1`, 2 overhead
  bytes); 256 would force `OP_PUSHDATA2` (3 overhead bytes). `OP_2DROP` discards
  two pushes with one byte. Net density: `510 / 515 ≈ 99.0%`.
* **34-byte output** — the P2TR `scriptPubKey` `OP_1 <32-byte x-only key>` is
  exactly 34 bytes; the single-leaf control block is 33 bytes.

Result: **≈ 3.96 MB of arbitrary data per block**, ~99% dense, every tx BIP-110
compliant.

### ord-compatible envelope

The data envelope follows the canonical form from
[ordinals/ord #4545](https://github.com/ordinals/ord/pull/4545) (the reference
BIP-110 envelope parser): a `"ord"` protocol-id push, then ≤255-byte data
pushes, all balanced back to stack-depth-0 with `OP_2DROP`/`OP_DROP`. The
envelope is **stack-depth-neutral**, so a real spend condition
(`<pubkey> OP_CHECKSIG`) sits *outside* it — data carried by an authenticated,
non-anyone-can-spend output.

### Auth modes

| `--auth` | Tapleaf shape | Witness | Notes |
|----------|---------------|---------|-------|
| `none` (default) | `<envelope> OP_1` | `[script, control_block]` | Anyone-can-spend; simplest. |
| `checksig` | `<pubkey> OP_CHECKSIG <envelope>` | `[schnorr_sig, script, control_block]` | Reveal gated by a Schnorr signature; not anyone-can-spend. |

---

## Install / build

```bash
cargo build --release
cargo test          # 19 unit tests
```

## CLI

```bash
# Weight/efficiency projection for a blob (uses dummy prevouts — not broadcastable):
bip110pack pack --input big.bin

# Print the P2TR address to fund for a data reveal:
bip110pack commit --input data.bin --auth checksig --network regtest

# Build the signed reveal tx spending a funded UTXO (raw hex to stdout):
bip110pack build-spend --input data.bin --auth checksig --network regtest \
  --prevout <txid:vout> --prevout-value <sat> --fee <sat> --to <address>

# Independently re-check any tx against the BIP-110 rules:
bip110pack verify <txhex>

# Recover the embedded bytes from a reveal tx's witness:
bip110pack extract <txhex> --out recovered.bin
```

`bip110pack verify` is an **independent** re-derivation of every BIP-110 rule
(C1–C10) straight from the raw transaction — it does not trust the generator.

---

## End-to-end regtest demo

```bash
./scripts/regtest-demo.sh
```

Spins up a throwaway regtest node, funds a Taproot commit address, builds the
data-carrying reveal tx, **mines it directly into a block** (the miner-inclusion
path), and proves three things for both auth modes:

1. our independent BIP-110 checker **PASSES** the reveal tx;
2. the node **accepts the block** — `generateblock` consensus-validates every tx
   it includes, so acceptance is proof of consensus validity;
3. the **exact bytes** are recovered from the mined witness.

Sample output (Bitcoin Core v30, regtest):

```
== Reveal demo — auth=checksig, payload=3810 bytes
commit address: bcrt1p6ud3dd8...r35acsm4h3z0
funded: 5de5a548...5fa7f272:0  value=2000000 sat (confirmed)
      witness items:   3
      BIP-110 check:   PASS
--- generateblock (miner inclusion; consensus-validated) ---
    block weight: 5207 WU
    in block:     true
    round-trip:   OK — 3810 bytes recovered from the mined block match the input

== Max block-fill projection (bip110pack pack)
      bytes packed:     3958620
      block fill:       99.95%
      efficiency:       99.019%
      BIP-110 check:    all 1 tx(s) PASS
```

### Proving it against Bitcoin Knots

[Bitcoin Knots](https://bitcoinknots.org/) is the node shipping the stricter
datacarrier / BIP-110-style enforcement, so getting these transactions accepted
by a Knots regtest node is the strongest compliance proof. The harness is
**node-agnostic** — point it at any `bitcoind`/`bitcoin-cli` pair:

```bash
BITCOIND=/path/to/knots/bin/bitcoind \
BITCOIN_CLI=/path/to/knots/bin/bitcoin-cli \
./scripts/regtest-demo.sh
```

> **Policy vs consensus.** Large data transactions are non-standard to *relay*
> (mempool policy), which is why we mine via `generateblock` — the exact path a
> miner uses to include a transaction directly. The harness also prints
> `testmempoolaccept` so you can see the relay verdict (which is where Knots'
> stricter policy differs from Core).

---

## BIP-110 compliance checklist (enforced by `bip110::validate`)

| # | Rule | How we satisfy it |
|---|------|-------------------|
| C1 | Output scriptPubKey ≤ 34 bytes | P2TR spk is exactly 34 bytes |
| C2 | OP_RETURN ≤ 83 bytes | not used |
| C3 | Every push payload ≤ 256 bytes | 255-byte chunks; validator scans pushes |
| C4 | Non-exempt witness items ≤ 256 bytes | only the exempt tapleaf script is larger |
| C5 | No Taproot annex | last witness item is the control block (0xc0/0xc1, never 0x50) |
| C6 | Control block ≤ 257 bytes | single-leaf = 33 bytes |
| C7 | No `OP_SUCCESS*` in tapscript | only push/`OP_2DROP`/`OP_DROP`/`OP_1`/`OP_CHECKSIG` |
| C8 | No executed `OP_IF`/`OP_NOTIF` | none emitted (validator conservatively bans presence) |
| C9 | Defined witness/leaf version | witness v1 output, TapScript leaf 0xc0 |
| C10 | Grandfathering | spend post-activation UTXOs |

The validator only treats a spend as a Taproot script-path spend when the last
witness item is a well-formed control block (`len == 33 + 32·m` and
`first & 0xfe == 0xc0`); otherwise every item is subject to the 256-byte cap.

---

## Layout

```
src/tapscript.rs      envelope builder (ord-compatible) + Auth modes + extractor
src/taproot_spend.rs  Taproot commit/reveal, deterministic keys, Schnorr signing
src/packer.rs         fill a block to ~4 MWU, weight accounting
src/bip110.rs         independent BIP-110 re-checker (C1–C10)
src/main.rs           CLI: pack / commit / build-spend / verify / extract
scripts/regtest-demo.sh   live end-to-end proof against bitcoind/knots
```

## Disclaimer

Research / demonstration tool for understanding the consensus surface of the
BIP-110 draft. Use on your own nodes and networks.

## License

MIT © Richard J. Safier
