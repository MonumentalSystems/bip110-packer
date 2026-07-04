# bip110-packer

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

## Encoding channels

The tapleaf scheme above is the densest, but it's not the only BIP-110-compliant
way to carry data. `--channel <name>` (on `commit` / `build-spend` / `extract`)
selects among **seven** channels, each exploiting a different corner of the rules.
Every one is proven end-to-end by `scripts/channels-demo.sh` (built → mined via
`generateblock` → recovered from the mined tx). `--compress` adds a pure-Rust
DEFLATE pre-pass that composes with all of them.

| `--channel` | Where the data lives | Capacity | Cost | Notes |
|---|---|---|---|---|
| `tapleaf` *(default)* | tapleaf `push`/`OP_2DROP` pushes | unbounded | 1 WU/B | best bulk (~3.96 MB/block) |
| `control-block` | internal key + Merkle sibling hashes | ~224 B/input | 1 WU/B | **novel**; looks like a normal deep-tree spend |
| `witness-args` | witness stack items the script drops | ~255 KB/input | 1 WU/B | keeps the script tiny |
| `p2wsh-envelope` | v0 P2WSH `OP_FALSE OP_IF … OP_ENDIF` | ~9.9 KB/input | 1 WU/B | the classic envelope — `OP_IF` is legal in v0 |
| `op-return` | `OP_RETURN` outputs (≤80 B each) | 80 B/output | 4 WU/B | the "blessed" channel |
| `fake-key` | 32-B P2TR programs (unspendable) | 32 B/output | 4 WU/B | UTXO-set bloat — worst case |
| `stego` | `nSequence` + output-amount low bits | ~2 B/output | 4 WU/B | fields BIP-110 doesn't restrict |

Commit/reveal channels (`tapleaf`, `control-block`, `witness-args`, `p2wsh-envelope`)
fund a P2TR/P2WSH commit address then reveal; output-only channels (`op-return`,
`fake-key`, `stego`) spend an existing UTXO and write the data into outputs.

```bash
# any channel, same commit → fund → reveal → extract flow:
bip110-packer commit     --channel control-block --input data.bin --network regtest
bip110-packer build-spend --channel control-block --compress --input data.bin \
  --prevout <txid:vout> --prevout-value <sat> --fee <sat> --to <addr> --network regtest
bip110-packer extract    --channel control-block <txhex>          # recovers the bytes
```

The **control-block** channel is the most novel: on a Taproot script-path spend you
never sign with the internal key, and the Merkle sibling hashes in the control
block are unconstrained — so the internal key (~31 B) and up to 7 siblings (32 B
each) are pure data, computed into a valid taproot commitment. It's compliant
(control block ≤ 257 B), recoverable, and indistinguishable from an ordinary deep
script-tree spend.

---

## Install / build

```bash
cargo build --release            # binary: target/release/bip110-packer
cargo test                       # 67 tests (61 unit + 6 enforcement)
cargo install --path .           # install the `bip110-packer` CLI
```

## CI & release

* **`.github/workflows/ci.yml`** — on every push to `main` / PR: `cargo fmt --check`,
  `cargo clippy -D warnings`, release build, the full test suite, and a
  `cargo publish --dry-run`. (The `regtest-demo` / `enforce-demo` scripts need a
  live `bitcoind` and are run manually, not in CI.)
* **`.github/workflows/publish.yml`** — on pushing a `vX.Y.Z` tag: verifies the tag
  matches the `Cargo.toml` version, tests, then `cargo publish` to crates.io.
  Requires a `CRATES_IO_TOKEN` repository secret. Release:

  ```bash
  # bump `version` in Cargo.toml, commit, then:
  git tag v0.1.0 && git push origin v0.1.0
  ```

  (The crate publishes as **`bip110-packer`** — matching the repo. Confirm the name
  is free on crates.io before the first publish.)

## CLI

```bash
# Weight/efficiency projection for a blob (uses dummy prevouts — not broadcastable):
bip110-packer pack --input big.bin

# Print the P2TR address to fund for a data reveal:
bip110-packer commit --input data.bin --auth checksig --network regtest

# Build the signed reveal tx spending a funded UTXO (raw hex to stdout):
bip110-packer build-spend --input data.bin --auth checksig --network regtest \
  --prevout <txid:vout> --prevout-value <sat> --fee <sat> --to <address>

# Independently re-check any tx against the BIP-110 rules:
bip110-packer verify <txhex>

# Recover the embedded bytes from a reveal tx's witness:
bip110-packer extract <txhex> --out recovered.bin
```

`bip110-packer verify` is an **independent** re-derivation of every BIP-110 rule
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

== Max block-fill projection (bip110-packer pack)
      bytes packed:     3958620
      block fill:       99.95%
      efficiency:       99.019%
      BIP-110 check:    all 1 tx(s) PASS
```

### Proving it against Bitcoin Knots

[Bitcoin Knots](https://bitcoinknots.org/) ships the stricter datacarrier /
BIP-110-style relay policy, so it's the most interesting node to run against. The
harness is **node-agnostic** — a helper downloads the official Knots binaries for
your platform and prints the env vars to point the harness at them:

```bash
eval "$(./scripts/fetch-knots.sh)"   # downloads Knots, exports BITCOIND/BITCOIN_CLI
./scripts/regtest-demo.sh            # same demo, now on Knots
```

(or point `BITCOIND` / `BITCOIN_CLI` at any `bitcoind`/`bitcoin-cli` pair yourself.)

**Observed result — the policy/consensus split is exactly what BIP-110 is about.**
The same reveal transaction, run against both nodes:

| | Bitcoin Core v30 | Bitcoin Knots v29.3 |
|---|---|---|
| `bip110-packer verify` (our checker) | PASS | PASS |
| `testmempoolaccept` (relay policy) | `allowed=true` | **`allowed=false: bad-witness-witness-size`** |
| `generateblock` (consensus / miner inclusion) | **mined** | **mined** |
| bytes recovered from the mined block | exact match | exact match |

Knots **rejects the tx from relay** under its stricter witness-size policy, yet
the very same tx is **consensus-valid and mines into a Knots block** — because
BIP-110's data limits (the ones `bip110-packer` respects) are the *consensus* rules,
distinct from a node's *relay* policy. This is why the packing path mines via
`generateblock` (the miner-inclusion path a real block producer uses) rather than
relying on the P2P mempool. `bad-witness-witness-size` is a Knots **standardness**
verdict, not a BIP-110 consensus violation.

---

## Node-enforced BIP-110 consensus (the real proof)

A stock Core/Knots node has no BIP-110 *consensus* rules, so it will happily mine
a data tx that breaks them. The **BIP-110 activation client**
([`dathonohm/bitcoin`](https://github.com/dathonohm/bitcoin), a Knots fork — see
[bip110.org](https://bip110.org)) adds the `reduced_data` versionbits deployment
and the consensus rules. Fetch it and drive the enforcement demo:

```bash
eval "$(./scripts/fetch-bip110-node.sh)"   # downloads the enforcing build, exports BITCOIND/BITCOIN_CLI
./scripts/enforce-demo.sh                  # auto-detects the enforcing build, runs the contrast
```

On regtest the deployment is driven to ACTIVE with
`-vbparams=reduced_data:0:<timeout>` and ~432 mined blocks. `enforce-demo.sh`
builds a **deliberately non-compliant** reveal for each rule
(`bip110-packer ... --violate {push,opif,opsuccess,output}`) and runs each through
the node **twice on the same binary** — with `reduced_data` inactive, then active:

| violation | `bip110-packer verify` | node, `reduced_data` **inactive** | node, `reduced_data` **active** |
|---|---|---|---|
| C3 oversized push | FAIL | MINED | **REJECTED** — `Push value size limit exceeded` |
| C8 `OP_IF` in tapscript | FAIL | MINED | **REJECTED** — `OP_IF/NOTIF argument must be minimal in tapscript` |
| C7 `OP_SUCCESS` in tapscript | FAIL | MINED | **REJECTED** — `OP_SUCCESSx reserved for soft-fork upgrades` |
| C1 oversized output | FAIL | MINED | **REJECTED** — `bad-txns-vout-script-toolarge` |
| *(compliant control)* | PASS | MINED | MINED |

Same binary, same transactions — the **only** difference is deployment
activation, which proves the rejections are BIP-110-gated and not some universal
rule. `generateblock` runs full `TestBlockValidity`, so a rejection is a genuine
**consensus** verdict. The activation client is also what makes the packer's
compliance claim node-checkable end-to-end, not just self-asserted.

The violation generator is exercised in CI-able unit form too — `cargo test`
includes `tests/enforcement.rs`, which asserts `bip110::validate` rejects each of
C1/C3/C6/C7/C8 and accepts the compliant control.

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
src/main.rs           CLI: pack / commit / build-spend / verify / extract (--channel / --compress / --violate)
src/channels/         seven encoding channels (control-block, witness-args, p2wsh-envelope, op-return, fake-key, stego) + dispatch
src/framing.rs        optional DEFLATE (--compress) pre-pass, composes with every channel
tests/enforcement.rs  battery: validator rejects each rule (C1/C3/C6/C7/C8)
scripts/regtest-demo.sh      live end-to-end proof against bitcoind/knots
scripts/channels-demo.sh     mine + round-trip every encoding channel
scripts/enforce-demo.sh      violation vs enforcement contrast (auto-detects the enforcing build)
scripts/fetch-knots.sh       download official Knots binaries for this platform
scripts/fetch-bip110-node.sh download the BIP-110 enforcing build (dathonohm/bitcoin)
```

## Disclaimer

Research / demonstration tool for understanding the consensus surface of the
BIP-110 draft. Use on your own nodes and networks.

## License

MIT © Richard J. Safier
