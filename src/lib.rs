//! # bip110-packer
//!
//! Maximally pack a single 4,000,000-weight-unit Bitcoin block with the most
//! arbitrary bytes possible while keeping every transaction compliant with
//! **BIP-110 ("Reduced Data Temporary Softfork")**.
//!
//! ## Strategy
//!
//! Data is carried inside a **Taproot (v1) script-path spend**. The tapleaf
//! script is a long run of `push <=256-byte chunk>` opcodes whose pushes are
//! immediately discarded with `OP_2DROP`, terminated by `OP_1` so the script
//! finishes with exactly one truthy stack element (a BIP342 *consensus*
//! requirement, stricter than legacy cleanstack).
//!
//! Why this shape:
//! * Witness bytes get the **4x weight discount** (1 WU/byte vs 4 WU/byte for
//!   base bytes), and BIP342 removes both the 10,000-byte script-size limit and
//!   the 201-opcode limit for tapscript, so a single tapscript can approach the
//!   whole block weight.
//! * The tapleaf script itself is **exempt** from BIP-110's 256-byte
//!   witness-item cap. Individual `OP_PUSHDATA` payloads *inside* the script are
//!   still capped at 256 bytes, so we chunk at 255 bytes.
//! * We cannot use the Ordinals `OP_FALSE OP_IF <data> OP_ENDIF` envelope
//!   because BIP-110 makes any tapscript that **executes** `OP_IF`/`OP_NOTIF`
//!   invalid. We cannot stream everything to the altstack with `OP_TOALTSTACK`
//!   because the combined main+alt stack is capped at 1000 elements. Push/2DROP
//!   keeps stack depth at 2 forever.
//!
//! ## Chunk density
//!
//! Chunking at **255 bytes with `OP_PUSHDATA1`** (2 overhead bytes) and dropping
//! pairs with a single `OP_2DROP` (0.5 byte amortized per chunk) yields
//! `2*(2+255)+1 = 515` script bytes carrying `510` data bytes → **99.03%**
//! script density. 256-byte chunks would force the less-efficient `OP_PUSHDATA2`
//! (3 overhead bytes).
//!
//! ## Throughput
//!
//! One transaction / one input / one giant single-leaf tapleaf is provably
//! optimal (each extra tx wastes ~376 WU of base bytes, each extra input
//! ~203 WU). After coinbase and framing overhead, a 4,000,000-WU block holds
//! roughly **3,959,000 bytes (~3.96 MB)** of arbitrary data.
//!
//! ## Modules
//!
//! * [`tapscript`] — chunk bytes into 255-byte pieces and emit push/OP_2DROP…OP_1.
//! * [`taproot_spend`] — Taproot output + script-path spend with a deterministic
//!   (fixed-bytes, no-RNG) internal key.
//! * [`packer`] — fill a block up to ~4,000,000 WU, tracking cumulative weight.
//! * [`bip110`] — an *independent* BIP-110 compliance re-checker.
//! * [`framing`] — 1-byte header + optional DEFLATE compression pre-pass.
//! * [`channels`] — pluggable data-encoding channels (tapleaf, control-block,
//!   witness-args, p2wsh-envelope, op-return, fake-key, stego).

pub mod bip110;
pub mod channels;
pub mod framing;
pub mod packer;
pub mod taproot_spend;
pub mod tapscript;
