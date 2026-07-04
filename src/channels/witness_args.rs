//! Witness-args channel — **COMMIT/REVEAL**.
//!
//! A Taproot script-path spend where the data lives in the *initial witness
//! stack items* — the "script arguments" a tapleaf sees before it runs. The
//! tapleaf script is nothing but a run of `OP_2DROP`/`OP_DROP` sized to consume
//! exactly the `N` pushed args, terminated by `OP_1` so the final stack is the
//! single truthy element BIP342 requires.
//!
//! Reveal witness layout (bottom → top):
//!
//! ```text
//! [ arg_0, arg_1, …, arg_{N-1}, tapleaf_script, control_block ]
//! ```
//!
//! * `arg_0 … arg_{N-1}` — the `framed` payload chopped into `<= 256`-byte
//!   ([`ARG_SIZE`]) items. Each is a **non-exempt** witness item, so BIP-110 C4
//!   (`<= 256` bytes) is the binding per-item constraint.
//! * `tapleaf_script` — the drop script (exempt from C4); contains no push, no
//!   `OP_IF`/`OP_NOTIF` (C8), and no `OP_SUCCESS*` (C7).
//! * `control_block` — a 33-byte single-leaf control block (C6 `<= 257`).
//!
//! The commitment binds only `N` (the arg count), via the drop script; the data
//! itself rides in the witness, so `commit_address` is reproducible from
//! `framed`'s length. Per-input capacity is bounded by the tapscript stack limit
//! [`MAX_STACK_SIZE`] (1000): up to ~1000 args × 256 bytes ≈ 256 KB per input.

use anyhow::{anyhow, Result};
use bitcoin::absolute::LockTime;
use bitcoin::key::Secp256k1;
use bitcoin::opcodes::all::{OP_2DROP, OP_DROP, OP_PUSHNUM_1};
use bitcoin::script::Builder;
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

use crate::taproot_spend::internal_key;

/// Bytes per witness-stack data item. The BIP-110 C4 cap is `<= 256`, and 256 is
/// exactly on the boundary (the check rejects only `> 256`), so this is the
/// densest legal item size.
pub const ARG_SIZE: usize = 256;

/// Tapscript initial-stack element limit. The reveal places `N` data args on the
/// stack before the drop script runs, so `N` must not exceed this.
pub const MAX_STACK_SIZE: usize = 1000;

/// Number of `ARG_SIZE`-byte witness args needed to carry `framed`.
fn num_args(framed: &[u8]) -> usize {
    framed.chunks(ARG_SIZE).count()
}

/// The tapleaf drop script for `n_args` witness arguments:
/// `{ OP_2DROP }*(n/2) [ OP_DROP ]?(n odd) OP_1`.
///
/// It pops exactly `n_args` items (in pairs, plus a lone `OP_DROP` when odd),
/// then pushes `OP_1`, leaving the stack as the single truthy element BIP342
/// demands. It contains no pushes (so no C3 concern), no `OP_IF`/`OP_NOTIF`
/// (C8), and no `OP_SUCCESS*` (C7).
fn drop_script(n_args: usize) -> ScriptBuf {
    let mut b = Builder::new();
    let mut remaining = n_args;
    while remaining >= 2 {
        b = b.push_opcode(OP_2DROP);
        remaining -= 2;
    }
    if remaining == 1 {
        b = b.push_opcode(OP_DROP);
    }
    b.push_opcode(OP_PUSHNUM_1).into_script()
}

/// Single-leaf Taproot commitment to the drop script for `n_args` args.
struct Bundle {
    /// The tapleaf drop script.
    script: ScriptBuf,
    /// 33-byte single-leaf control block for the script-path spend.
    control_block: ControlBlock,
    /// Full spend info (used for the output-key merkle root).
    spend_info: TaprootSpendInfo,
}

/// Build the single-leaf commitment for a drop script consuming `n_args` items.
///
/// Errors if `n_args` would overflow the tapscript stack limit
/// ([`MAX_STACK_SIZE`]); both [`commit_address`] and [`build_reveal`] route
/// through here, so they agree on when a payload is too large for one input.
fn build_bundle(n_args: usize) -> Result<Bundle> {
    if n_args > MAX_STACK_SIZE {
        return Err(anyhow!(
            "witness-args payload needs {n_args} stack items > MAX_STACK_SIZE {MAX_STACK_SIZE}; \
             split it across multiple inputs"
        ));
    }

    let secp = Secp256k1::new();
    let ik = internal_key(&secp);
    let script = drop_script(n_args);

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .map_err(|e| anyhow!("add_leaf: {e:?}"))?
        .finalize(&secp, ik)
        .map_err(|_| anyhow!("incomplete taproot tree"))?;

    let control_block = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| anyhow!("script not present in tree"))?;

    Ok(Bundle {
        script,
        control_block,
        spend_info,
    })
}

/// Commit address whose reveal witness will carry `framed` as script arguments.
///
/// The commitment depends only on the number of args (`framed.len()` chunked by
/// [`ARG_SIZE`]), so it is fully reproducible from `framed` + `network`.
pub fn commit_address(framed: &[u8], network: Network) -> Result<Address> {
    let secp = Secp256k1::new();
    let ik = internal_key(&secp);
    let bundle = build_bundle(num_args(framed))?;
    Ok(Address::p2tr(
        &secp,
        ik,
        bundle.spend_info.merkle_root(),
        network,
    ))
}

/// Reveal transaction that spends `prevout` and carries `framed` in its witness
/// stack items, paying `prevout_value - fee` to `to`.
///
/// Witness = `[ arg_0, …, arg_{N-1}, tapleaf_script, control_block ]`.
pub fn build_reveal(
    framed: &[u8],
    prevout: OutPoint,
    prevout_value: Amount,
    to: &ScriptBuf,
    fee: Amount,
    network: Network,
) -> Result<Transaction> {
    // The raw tx is network-agnostic; `network` is accepted for signature parity
    // with the other commit/reveal channels.
    let _ = network;

    let bundle = build_bundle(num_args(framed))?;

    let out_value = prevout_value
        .checked_sub(fee)
        .ok_or_else(|| anyhow!("fee {fee} exceeds prevout value {prevout_value}"))?;

    let txin = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    let txout = TxOut {
        value: out_value,
        script_pubkey: to.clone(),
    };
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    // Data args first (bottom of stack), then the exempt tapleaf script, then the
    // control block (last item, first byte 0xc0 — never the 0x50 annex tag).
    let mut witness = Witness::new();
    for chunk in framed.chunks(ARG_SIZE) {
        witness.push(chunk);
    }
    witness.push(bundle.script.as_bytes());
    witness.push(bundle.control_block.serialize());
    tx.input[0].witness = witness;

    Ok(tx)
}

/// Recover the **framed** bytes from a witness-args reveal transaction.
///
/// The data args are every witness item except the final two (the tapleaf script
/// and the control block); concatenate them in order.
pub fn decode(tx: &Transaction) -> Result<Vec<u8>> {
    let witness = &tx
        .input
        .first()
        .ok_or_else(|| anyhow!("tx has no inputs"))?
        .witness;
    let n = witness.len();
    if n < 2 {
        return Err(anyhow!(
            "witness has {n} item(s); expected a script-path spend (>=2: script + control block)"
        ));
    }

    let mut framed = Vec::new();
    for item in witness.iter().take(n - 2) {
        framed.extend_from_slice(item);
    }
    Ok(framed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot_spend::dummy_prevout;

    /// A throwaway 34-byte P2TR destination scriptPubKey for reveal outputs.
    fn dest_spk() -> ScriptBuf {
        crate::taproot_spend::commit_address(
            b"dest",
            crate::tapscript::Auth::None,
            Network::Regtest,
        )
        .unwrap()
        .script_pubkey()
    }

    #[test]
    fn commit_address_is_deterministic() {
        let framed = b"\x00witness-args commit address";
        let a = commit_address(framed, Network::Regtest).unwrap();
        let b = commit_address(framed, Network::Regtest).unwrap();
        assert_eq!(a, b, "commit address must be reproducible");
    }

    #[test]
    fn roundtrip_various_lengths_and_bip110_valid() {
        let to = dest_spk();
        // Includes the C4 boundary (256) and just past it (257) so both the
        // single-arg and multi-arg (OP_2DROP + odd OP_DROP) paths are exercised.
        for len in [0usize, 1, 100, 255, 256, 257, 512, 513, 700, 4096] {
            let framed: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let tx = build_reveal(
                &framed,
                dummy_prevout(0),
                Amount::from_sat(100_000),
                &to,
                Amount::from_sat(1_000),
                Network::Regtest,
            )
            .unwrap();

            let back = decode(&tx).unwrap();
            assert_eq!(back, framed, "roundtrip failed for len {len}");

            assert_eq!(
                crate::bip110::validate(&tx),
                Ok(()),
                "BIP-110 validation failed for len {len}"
            );

            // Every data arg (all items but the last two) must be <= 256 (C4).
            let items: Vec<&[u8]> = tx.input[0].witness.iter().collect();
            for item in &items[..items.len() - 2] {
                assert!(
                    item.len() <= 256,
                    "witness data arg {} bytes > 256 for len {len}",
                    item.len()
                );
            }
            // Output pays prevout_value - fee.
            assert_eq!(tx.output[0].value, Amount::from_sat(99_000));
        }
    }

    #[test]
    fn witness_layout_is_args_then_script_then_control_block() {
        let framed: Vec<u8> = (0..600u32).map(|i| i as u8).collect(); // -> 3 args (256+256+88)
        let to = dest_spk();
        let tx = build_reveal(
            &framed,
            dummy_prevout(1),
            Amount::from_sat(10_000),
            &to,
            Amount::from_sat(500),
            Network::Regtest,
        )
        .unwrap();

        let items: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert_eq!(items.len(), 5, "3 data args + script + control block");
        assert_eq!(items[0].len(), 256);
        assert_eq!(items[1].len(), 256);
        assert_eq!(items[2].len(), 88);
        // Control block: single-leaf, 33 bytes, defined TapScript leaf version.
        let cb = items[4];
        assert_eq!(cb.len(), 33);
        assert_eq!(cb[0] & 0xfe, 0xc0);
    }

    #[test]
    fn drop_script_has_no_banned_opcodes() {
        use bitcoin::script::Instruction;
        for n in [0usize, 1, 2, 3, 8, 999] {
            let script = drop_script(n);
            for ins in script.instructions() {
                match &ins {
                    Ok(Instruction::Op(op)) => {
                        let b = op.to_u8();
                        assert_ne!(b, 0x63, "OP_IF present");
                        assert_ne!(b, 0x64, "OP_NOTIF present");
                        assert!(!crate::bip110::is_op_success(b), "OP_SUCCESS present");
                    }
                    // The drop script contains no push instructions at all.
                    Ok(Instruction::PushBytes(_)) => panic!("drop script must contain no pushes"),
                    Err(e) => panic!("malformed drop script: {e}"),
                }
            }
        }
    }

    #[test]
    fn oversized_payload_is_rejected() {
        // MAX_STACK_SIZE + 1 args worth of bytes must be refused (both commit and
        // reveal), rather than silently producing an unspendable stack.
        let framed = vec![0xABu8; ARG_SIZE * (MAX_STACK_SIZE + 1)];
        assert!(commit_address(&framed, Network::Regtest).is_err());
        assert!(build_reveal(
            &framed,
            dummy_prevout(0),
            Amount::from_sat(100_000),
            &dest_spk(),
            Amount::from_sat(1_000),
            Network::Regtest,
        )
        .is_err());
    }
}
