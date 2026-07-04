//! BIP-110 data-encoding **channels**.
//!
//! A *channel* is one concrete way to embed an opaque, already-[`framed`] byte
//! string into a Bitcoin transaction while staying BIP-110 compliant. The
//! original Taproot tapleaf `push`/`OP_2DROP` scheme (see [`crate::tapscript`] /
//! [`crate::taproot_spend`]) is the [`Channel::Tapleaf`] channel; every other
//! variant lives in its own submodule under `src/channels/`.
//!
//! # Adding / filling in a channel
//!
//! A channel implementer edits **only their own `src/channels/<name>.rs` file**.
//! They never touch `mod.rs` or `main.rs`. Each submodule exposes a fixed set of
//! free functions (documented below); the dispatchers in this module call them.
//!
//! ## Payload contract
//!
//! Every function takes / returns **framed** bytes (the output of
//! [`crate::framing::frame`]). A channel treats them as opaque: it does not
//! compress, does not add its own header, and does not interpret them. The CLI
//! frames before building and [`crate::framing::unframe`]s after decoding.
//!
//! ## Interface each submodule must implement
//!
//! Commit/reveal channels ([`Channel::ControlBlock`], [`Channel::WitnessArgs`],
//! [`Channel::P2wshEnvelope`]) — a two-transaction flow (fund a commit address,
//! then reveal by spending it):
//!
//! ```ignore
//! pub fn commit_address(framed: &[u8], network: bitcoin::Network)
//!     -> anyhow::Result<bitcoin::Address>;
//! pub fn build_reveal(
//!     framed: &[u8],
//!     prevout: bitcoin::OutPoint,
//!     prevout_value: bitcoin::Amount,
//!     to: &bitcoin::ScriptBuf,
//!     fee: bitcoin::Amount,
//!     network: bitcoin::Network,
//! ) -> anyhow::Result<bitcoin::Transaction>;
//! pub fn decode(tx: &bitcoin::Transaction) -> anyhow::Result<Vec<u8>>; // FRAMED bytes
//! ```
//!
//! * `commit_address` — the P2TR (or other) address to fund so `framed` can later
//!   be revealed by spending it. Must be reproducible from `framed` + `network`.
//! * `build_reveal` — a fully-formed transaction that spends `prevout` (value
//!   `prevout_value`), carries all of `framed`, pays `prevout_value - fee` to
//!   `to`, and is BIP-110 compliant.
//! * `decode` — recover the **framed** bytes from such a reveal transaction. The
//!   caller unframes; do not unframe here.
//!
//! Output-only channels ([`Channel::OpReturn`], [`Channel::FakeKey`]) and the
//! transaction-field [`Channel::Stego`] channel — a single transaction that spends
//! `prevout` and emits the data outputs plus a change output:
//!
//! ```ignore
//! pub fn build_tx(
//!     framed: &[u8],
//!     prevout: bitcoin::OutPoint,
//!     prevout_value: bitcoin::Amount,
//!     change_to: &bitcoin::ScriptBuf,
//!     fee: bitcoin::Amount,
//!     network: bitcoin::Network,
//! ) -> anyhow::Result<bitcoin::Transaction>;
//! pub fn decode(tx: &bitcoin::Transaction) -> anyhow::Result<Vec<u8>>; // FRAMED bytes
//! ```
//!
//! * `build_tx` — spend `prevout`, write `framed` into the data outputs, and send
//!   `prevout_value - fee - dust(data outputs)` back to `change_to`.
//! * `decode` — recover the **framed** bytes from such a transaction.

use anyhow::{anyhow, Result};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction};

pub mod control_block;
pub mod fake_key;
pub mod op_return;
pub mod p2wsh_envelope;
pub mod stego;
pub mod witness_args;

/// Selects the data-encoding channel.
///
/// The kebab-case CLI values are: `tapleaf`, `control-block`, `witness-args`,
/// `p2wsh-envelope`, `op-return`, `fake-key`, `stego`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Channel {
    /// Taproot tapleaf `push`/`OP_2DROP` scheme (the original, unbounded channel).
    #[value(name = "tapleaf")]
    Tapleaf,
    /// Data packed into Taproot control-block merkle-path siblings (commit/reveal).
    #[value(name = "control-block")]
    ControlBlock,
    /// Data spread across non-exempt witness stack items (commit/reveal).
    #[value(name = "witness-args")]
    WitnessArgs,
    /// Data in a P2WSH witnessScript envelope (witness-v0; commit/reveal).
    #[value(name = "p2wsh-envelope")]
    P2wshEnvelope,
    /// Data in one or more `OP_RETURN` outputs (output-only).
    #[value(name = "op-return")]
    OpReturn,
    /// Data disguised as fake pubkeys inside standard-looking outputs (output-only).
    #[value(name = "fake-key")]
    FakeKey,
    /// Data encoded in transaction fields BIP-110 does not restrict (nSequence +
    /// output amounts).
    #[value(name = "stego")]
    Stego,
}

/// Whether a channel is commit/reveal (has a commit address) or output-only.
impl Channel {
    /// `true` if the channel funds a commit address then reveals it
    /// ([`Tapleaf`](Channel::Tapleaf), [`ControlBlock`](Channel::ControlBlock),
    /// [`WitnessArgs`](Channel::WitnessArgs),
    /// [`P2wshEnvelope`](Channel::P2wshEnvelope)); `false` for output-only /
    /// stego channels that emit data directly from a single tx.
    pub fn is_commit_reveal(self) -> bool {
        matches!(
            self,
            Channel::Tapleaf
                | Channel::ControlBlock
                | Channel::WitnessArgs
                | Channel::P2wshEnvelope
        )
    }
}

/// Per-transaction / per-input payload capacity of a channel in **framed** bytes,
/// or `None` when the channel is effectively unbounded (data scales with script
/// or witness size that BIP-110 does not cap).
///
/// * [`Tapleaf`](Channel::Tapleaf) — unbounded: the tapleaf script is exempt from
///   the witness-item cap, so one leaf can approach the whole block weight.
/// * [`ControlBlock`](Channel::ControlBlock) — `257 - 33 = 224` bytes per input
///   (the C6 control-block cap minus the 1-byte leaf/parity byte and the 32-byte
///   internal key; i.e. 7 merkle-sibling slots of 32 bytes).
/// * [`WitnessArgs`](Channel::WitnessArgs) — unbounded: any number of `<=256`-byte
///   (C4) witness items may precede the tapleaf/control-block.
/// * [`P2wshEnvelope`](Channel::P2wshEnvelope) — unbounded: the v0 witnessScript
///   is exempt from the witness-item cap.
/// * [`OpReturn`](Channel::OpReturn) — `80` bytes per `OP_RETURN` output (the C2
///   83-byte cap minus `OP_RETURN` + `OP_PUSHDATA1` + length overhead). Multiple
///   outputs raise the per-tx total.
/// * [`FakeKey`](Channel::FakeKey) — `32` bytes per fake-key output (a 34-byte C1
///   scriptPubKey carrying a 32-byte "pubkey"). Multiple outputs raise the total.
/// * [`Stego`](Channel::Stego) — unbounded in principle (spread across many
///   transaction fields), so no fixed cap is documented here.
pub fn max_payload(channel: Channel) -> Option<usize> {
    match channel {
        Channel::Tapleaf => None,
        Channel::ControlBlock => Some(224),
        Channel::WitnessArgs => None,
        Channel::P2wshEnvelope => None,
        Channel::OpReturn => Some(80),
        Channel::FakeKey => Some(32),
        Channel::Stego => None,
    }
}

/// Compute the commit address to fund for a `framed` payload on `channel`.
///
/// Returns `Ok(Some(addr))` for commit/reveal channels and `Ok(None)` for
/// output-only / stego channels (which have no commit step — call [`build`]
/// directly).
pub fn commit_address(
    channel: Channel,
    framed: &[u8],
    network: Network,
) -> Result<Option<Address>> {
    Ok(match channel {
        Channel::Tapleaf => Some(crate::taproot_spend::commit_address(
            framed,
            crate::tapscript::Auth::None,
            network,
        )?),
        Channel::ControlBlock => Some(control_block::commit_address(framed, network)?),
        Channel::WitnessArgs => Some(witness_args::commit_address(framed, network)?),
        Channel::P2wshEnvelope => Some(p2wsh_envelope::commit_address(framed, network)?),
        Channel::OpReturn | Channel::FakeKey | Channel::Stego => None,
    })
}

/// Build the data-carrying transaction for `channel`.
///
/// For commit/reveal channels this is the *reveal* tx (spending `prevout`, the
/// previously funded commit output, paying `prevout_value - fee` to `to`). For
/// output-only / stego channels this is the single data tx (spending `prevout`,
/// emitting the data outputs plus a change output to `to`). In both cases `to` is
/// the destination / change scriptPubKey.
pub fn build(
    channel: Channel,
    framed: &[u8],
    prevout: OutPoint,
    prevout_value: Amount,
    to: &ScriptBuf,
    fee: Amount,
    network: Network,
) -> Result<Transaction> {
    match channel {
        Channel::Tapleaf => crate::taproot_spend::build_signed_spend(
            framed,
            crate::tapscript::Auth::None,
            prevout,
            prevout_value,
            to,
            fee,
            network,
        ),
        Channel::ControlBlock => {
            control_block::build_reveal(framed, prevout, prevout_value, to, fee, network)
        }
        Channel::WitnessArgs => {
            witness_args::build_reveal(framed, prevout, prevout_value, to, fee, network)
        }
        Channel::P2wshEnvelope => {
            p2wsh_envelope::build_reveal(framed, prevout, prevout_value, to, fee, network)
        }
        Channel::OpReturn => op_return::build_tx(framed, prevout, prevout_value, to, fee, network),
        Channel::FakeKey => fake_key::build_tx(framed, prevout, prevout_value, to, fee, network),
        Channel::Stego => stego::build_tx(framed, prevout, prevout_value, to, fee, network),
    }
}

/// Recover the **framed** bytes carried by `tx` on `channel`. The caller unframes
/// (via [`crate::framing::unframe`]).
pub fn decode(channel: Channel, tx: &Transaction) -> Result<Vec<u8>> {
    match channel {
        Channel::Tapleaf => decode_tapleaf(tx),
        Channel::ControlBlock => control_block::decode(tx),
        Channel::WitnessArgs => witness_args::decode(tx),
        Channel::P2wshEnvelope => p2wsh_envelope::decode(tx),
        Channel::OpReturn => op_return::decode(tx),
        Channel::FakeKey => fake_key::decode(tx),
        Channel::Stego => stego::decode(tx),
    }
}

/// [`Channel::Tapleaf`] decode: read the tapleaf script (the second-to-last
/// witness item of the first input) and reconstruct the carried bytes, preferring
/// the ord-envelope payload and falling back to a raw push-concatenation.
fn decode_tapleaf(tx: &Transaction) -> Result<Vec<u8>> {
    use crate::tapscript::{extract_data, extract_ord_payload};

    let witness = &tx
        .input
        .first()
        .ok_or_else(|| anyhow!("tx has no inputs"))?
        .witness;
    let n = witness.len();
    if n < 2 {
        return Err(anyhow!(
            "input witness has {n} item(s); expected a taproot script-path spend (>=2)"
        ));
    }
    let script_bytes = witness
        .nth(n - 2)
        .ok_or_else(|| anyhow!("missing tapleaf script witness item"))?;
    let script = ScriptBuf::from(script_bytes.to_vec());

    let mut data = extract_ord_payload(&script);
    if data.is_empty() {
        data = extract_data(&script).map_err(|e| anyhow!(e))?;
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot_spend::dummy_prevout;

    #[test]
    fn commit_address_none_for_output_only_channels() {
        for ch in [Channel::OpReturn, Channel::FakeKey, Channel::Stego] {
            let addr = commit_address(ch, b"\x00data", Network::Regtest).unwrap();
            assert!(addr.is_none(), "{ch:?} must have no commit address");
        }
    }

    #[test]
    fn commit_address_some_for_commit_reveal_tapleaf() {
        let addr = commit_address(Channel::Tapleaf, b"\x00data", Network::Regtest).unwrap();
        assert!(addr.is_some(), "tapleaf must have a commit address");
    }

    #[test]
    fn tapleaf_build_and_decode_roundtrips_framed_bytes() {
        // Frame -> build (tapleaf) -> decode must return the exact framed bytes.
        let framed = crate::framing::frame(b"channel dispatch roundtrip", false);
        let to = commit_address(Channel::Tapleaf, &framed, Network::Regtest)
            .unwrap()
            .unwrap()
            .script_pubkey();
        let tx = build(
            Channel::Tapleaf,
            &framed,
            dummy_prevout(0),
            Amount::from_sat(100_000),
            &to,
            Amount::from_sat(1_000),
            Network::Regtest,
        )
        .unwrap();
        let recovered = decode(Channel::Tapleaf, &tx).unwrap();
        assert_eq!(recovered, framed);
        assert_eq!(
            crate::framing::unframe(&recovered).unwrap(),
            b"channel dispatch roundtrip"
        );
    }

    #[test]
    fn max_payload_bounds_are_reported() {
        assert_eq!(max_payload(Channel::Tapleaf), None);
        assert_eq!(max_payload(Channel::ControlBlock), Some(224));
        assert_eq!(max_payload(Channel::OpReturn), Some(80));
        assert_eq!(max_payload(Channel::FakeKey), Some(32));
    }
}
