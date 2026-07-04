//! OP_RETURN channel — **OUTPUT-ONLY**, the "blessed" data channel.
//!
//! Spend `prevout` and emit `K` `OP_RETURN` outputs, each carrying one push of
//! `framed` bytes, plus a single change output back to `change_to`.
//!
//! # Density / cost
//!
//! These are **base** (non-witness) bytes: an OP_RETURN output lives in the
//! transaction body, which is billed at **4 weight units per byte** — roughly
//! **4x worse** than witness-resident channels (tapleaf / control-block /
//! witness-args) whose payload bytes cost ~1 WU/byte. OP_RETURN is the
//! standardness-blessed, universally relayed channel; you pay for that in weight.
//!
//! # Layout of one data output
//!
//! ```text
//! scriptPubKey = OP_RETURN OP_PUSHDATA1 <len> <up-to-80 payload bytes>
//!                   1     +      1      +  1  +        <=80          = <=83
//! ```
//!
//! An 80-byte push uses `OP_PUSHDATA1` (opcode + 1 length byte), so the whole
//! scriptPubKey is exactly `1 + 1 + 1 + 80 = 83` bytes — the C2 cap. Hence the
//! per-output capacity of `80` framed bytes (see [`crate::channels::max_payload`]);
//! payloads longer than 80 bytes are chunked across multiple `OP_RETURN` outputs.
//!
//! # BIP-110
//!
//! * **C2** — every `OP_RETURN` scriptPubKey is `<= 83` bytes (guaranteed by the
//!   80-byte chunking above).
//! * **C1** — the change output is a normal (non-`OP_RETURN`) scriptPubKey and
//!   must be `<= 34` bytes; that is the caller's `change_to`.
//! * **C3** — each push payload is `<= 80 <= 256`.
//! * The single input carries no witness, so the witness rules (C4–C9) are inert.

use anyhow::{anyhow, Result};
use bitcoin::absolute::LockTime;
use bitcoin::script::{Instruction, PushBytes};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// Maximum payload bytes carried by one `OP_RETURN` output.
///
/// An 80-byte push is emitted with `OP_PUSHDATA1` (opcode + 1 length byte), so
/// the scriptPubKey is `OP_RETURN(1) + OP_PUSHDATA1(1) + len(1) + 80 = 83` bytes,
/// exactly the BIP-110 C2 cap. This matches [`crate::channels::max_payload`].
const MAX_OP_RETURN_PUSH: usize = 80;

/// Single transaction: spend `prevout`, emit the `OP_RETURN` data outputs and a
/// change output to `change_to` worth `prevout_value - fee`.
///
/// `framed` is chunked into `<= 80`-byte pieces, one `OP_RETURN` output per chunk
/// (each output value 0, since `OP_RETURN` outputs are provably unspendable). The
/// change output pays `prevout_value - fee` — the data outputs carry no value, so
/// there is no per-data-output dust to subtract.
pub fn build_tx(
    framed: &[u8],
    prevout: OutPoint,
    prevout_value: Amount,
    change_to: &ScriptBuf,
    fee: Amount,
    network: Network,
) -> Result<Transaction> {
    // The raw tx is network-agnostic; `network` is accepted for signature parity
    // with the other channels.
    let _ = network;

    let change_value = prevout_value
        .checked_sub(fee)
        .ok_or_else(|| anyhow!("fee {fee} exceeds prevout value {prevout_value}"))?;

    // One OP_RETURN output per <=80-byte chunk (empty `framed` yields no data
    // outputs, which `decode` round-trips back to an empty payload).
    let mut output: Vec<TxOut> = Vec::new();
    for chunk in framed.chunks(MAX_OP_RETURN_PUSH) {
        let push = <&PushBytes>::try_from(chunk)
            .map_err(|_| anyhow!("chunk of {} bytes exceeds the push limit", chunk.len()))?;
        output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new_op_return(push),
        });
    }

    // Change output last (a normal <=34-byte spk per C1; caller's responsibility).
    output.push(TxOut {
        value: change_value,
        script_pubkey: change_to.clone(),
    });

    let txin = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output,
    })
}

/// Recover the **framed** bytes from the transaction's `OP_RETURN` outputs.
///
/// Every `OP_RETURN` output is visited in output order and its pushed bytes are
/// concatenated — the exact inverse of [`build_tx`]'s chunking. Non-`OP_RETURN`
/// outputs (e.g. the change output) are ignored.
pub fn decode(tx: &Transaction) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for txout in &tx.output {
        let spk = &txout.script_pubkey;
        if !spk.is_op_return() {
            continue;
        }
        for ins in spk.instructions() {
            match ins {
                Ok(Instruction::PushBytes(pb)) => out.extend_from_slice(pb.as_bytes()),
                Ok(Instruction::Op(_)) => {}
                Err(e) => return Err(anyhow!("malformed OP_RETURN script: {e}")),
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot_spend::dummy_prevout;

    /// A throwaway, C1-compliant 34-byte (P2TR-shaped) change/destination spk:
    /// `OP_1 <32-byte push>`.
    fn dest_spk() -> ScriptBuf {
        let mut v = Vec::with_capacity(34);
        v.push(0x51); // OP_1 (witness v1)
        v.push(0x20); // push 32 bytes
        v.extend_from_slice(&[0x11u8; 32]);
        ScriptBuf::from(v)
    }

    fn build_for(framed: &[u8]) -> Transaction {
        build_tx(
            framed,
            dummy_prevout(0),
            Amount::from_sat(100_000),
            &dest_spk(),
            Amount::from_sat(1_000),
            Network::Regtest,
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_several_lengths() {
        // Boundaries around the 80-byte per-output chunk size, plus multi-output.
        for len in [0usize, 1, 79, 80, 81, 159, 160, 161, 500, 1_000] {
            let framed: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let tx = build_for(&framed);
            let back = decode(&tx).unwrap();
            assert_eq!(back, framed, "roundtrip failed for len {len}");
        }
    }

    #[test]
    fn every_op_return_spk_within_c2_cap() {
        let framed: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let tx = build_for(&framed);
        let mut data_outputs = 0usize;
        for txout in &tx.output {
            let spk = &txout.script_pubkey;
            if spk.is_op_return() {
                data_outputs += 1;
                assert!(
                    spk.len() <= 83,
                    "OP_RETURN scriptPubKey {} bytes > 83 (C2)",
                    spk.len()
                );
                assert_eq!(txout.value, Amount::from_sat(0), "data outputs are value 0");
            }
        }
        // ceil(500 / 80) == 7 OP_RETURN outputs.
        assert_eq!(
            data_outputs, 7,
            "expected 7 OP_RETURN outputs for 500 bytes"
        );
    }

    #[test]
    fn change_output_pays_prevout_minus_fee() {
        let framed: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let tx = build_for(&framed);
        let change = tx
            .output
            .last()
            .expect("at least the change output is present");
        assert!(
            !change.script_pubkey.is_op_return(),
            "last output is change"
        );
        assert_eq!(change.value, Amount::from_sat(99_000));
        assert!(
            change.script_pubkey.len() <= 34,
            "change spk must be <=34 (C1)"
        );
    }

    #[test]
    fn built_tx_passes_bip110_validate() {
        let framed: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let tx = build_tx(
            &framed,
            dummy_prevout(2),
            Amount::from_sat(50_000),
            &dest_spk(),
            Amount::from_sat(500),
            Network::Regtest,
        )
        .unwrap();
        assert_eq!(
            crate::bip110::validate(&tx),
            Ok(()),
            "built OP_RETURN tx must be BIP-110 compliant"
        );
    }

    #[test]
    fn fee_exceeding_value_errors() {
        let err = build_tx(
            b"\x00payload",
            dummy_prevout(0),
            Amount::from_sat(500),
            &dest_spk(),
            Amount::from_sat(1_000),
            Network::Regtest,
        );
        assert!(err.is_err(), "fee > prevout value must error");
    }
}
