//! Field-value channel — **OUTPUT-ONLY**.
//!
//! Encode `framed` bytes into transaction fields that BIP-110 does not constrain
//! at all: the input's `nSequence` and the output **amounts**. BIP-110 restricts
//! *scripts* (push sizes, output/script lengths, opcodes) — it says nothing about
//! sequence numbers or satoshi values, so this channel is invisible to every one
//! of its rules.
//!
//! # Layout
//!
//! ```text
//! nSequence(input 0) = framed.len()                 (u32, so payloads < 4 GiB)
//! output_i.value     = DUST_BASE + u16_be(framed[2i .. 2i+2])   for i in 0..ceil(len/2)
//! output_last        = change (prevout_value - fee - sum(data outputs))
//! ```
//!
//! Two payload bytes ride in each data output's amount (its value above a fixed
//! `DUST_BASE`); the exact byte count is carried in `nSequence`, so [`decode`]
//! knows how many outputs to read and how to trim the final (possibly 1-byte)
//! word. Transaction `version` is set to **1** so BIP-68 relative-locktime is not
//! enforced and an arbitrary `nSequence` has no side effect.
//!
//! Unlike [`crate::channels::fake_key`], the data outputs pay the caller's
//! `change_to` address — they are ordinary, spendable outputs, so this channel
//! adds no permanent UTXO-set bloat. The trade-off is **bandwidth**: only 2 bytes
//! per output (plus 4 bytes in `nSequence`), billed as base bytes. It is a
//! low-rate side channel, best for small markers/metadata, not bulk data.
//!
//! # BIP-110
//!
//! Every output pays `change_to` (a normal `<= 34`-byte scriptPubKey, C1); the
//! input carries no script data. `nSequence` and output values are outside
//! BIP-110's scope entirely, so nothing here can trip a rule.

use anyhow::{anyhow, ensure, Result};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// Baseline value each data output carries; the two payload bytes are added on
/// top as a `u16`, so a data output is `DUST_BASE ..= DUST_BASE + 65535` sat.
const DUST_BASE: Amount = Amount::from_sat(1_000);

/// Bytes carried per data output (in the low 16 bits of its amount).
const BYTES_PER_OUTPUT: usize = 2;

/// Single transaction: spend `prevout`, encode `framed` into `nSequence` + output
/// amounts, and pay the remainder to `change_to`.
///
/// The returned transaction is **unsigned** (empty scriptSig/witness on the
/// input), matching the other output-only channels; a wallet signs it before
/// broadcast, which preserves `version`, `nSequence`, and the output amounts.
pub fn build_tx(
    framed: &[u8],
    prevout: OutPoint,
    prevout_value: Amount,
    change_to: &ScriptBuf,
    fee: Amount,
    network: Network,
) -> Result<Transaction> {
    // The raw tx is network-agnostic; `network` is accepted for signature parity.
    let _ = network;

    let len = u32::try_from(framed.len()).map_err(|_| {
        anyhow!(
            "payload {} bytes exceeds the 32-bit length field",
            framed.len()
        )
    })?;

    // One output per 2 payload bytes; its value encodes the bytes above DUST_BASE.
    let mut output: Vec<TxOut> = Vec::new();
    let mut data_total: u64 = 0;
    for chunk in framed.chunks(BYTES_PER_OUTPUT) {
        let mut w = [0u8; BYTES_PER_OUTPUT];
        w[..chunk.len()].copy_from_slice(chunk);
        let piece = u16::from_be_bytes(w) as u64;
        let value = DUST_BASE.to_sat() + piece;
        data_total += value;
        output.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: change_to.clone(),
        });
    }

    let change_value = prevout_value
        .checked_sub(fee)
        .and_then(|v| v.checked_sub(Amount::from_sat(data_total)))
        .ok_or_else(|| anyhow!("prevout {prevout_value} too small for fee {fee} + data outputs"))?;
    output.push(TxOut {
        value: change_value,
        script_pubkey: change_to.clone(),
    });

    let txin = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        // The payload length rides in nSequence; version 1 disables BIP-68 so this
        // value carries no relative-locktime meaning.
        sequence: Sequence::from_consensus(len),
        witness: Witness::new(),
    };

    Ok(Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output,
    })
}

/// Recover the **framed** bytes from `nSequence` + the leading output amounts.
pub fn decode(tx: &Transaction) -> Result<Vec<u8>> {
    let seq = tx
        .input
        .first()
        .ok_or_else(|| anyhow!("stego tx has no inputs"))?
        .sequence
        .to_consensus_u32();
    let len = seq as usize;

    let n_data = len.div_ceil(BYTES_PER_OUTPUT);
    ensure!(
        tx.output.len() >= n_data,
        "declared length {len} needs {n_data} data outputs but tx has {}",
        tx.output.len()
    );

    let mut out = Vec::with_capacity(n_data * BYTES_PER_OUTPUT);
    for (i, txout) in tx.output[..n_data].iter().enumerate() {
        let piece = txout
            .value
            .to_sat()
            .checked_sub(DUST_BASE.to_sat())
            .ok_or_else(|| anyhow!("data output {i} value below DUST_BASE"))?;
        ensure!(
            piece <= u16::MAX as u64,
            "data output {i} encodes a value {piece} > u16::MAX"
        );
        out.extend_from_slice(&(piece as u16).to_be_bytes());
    }
    out.truncate(len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot_spend::dummy_prevout;

    /// A throwaway, C1-compliant 22-byte P2WPKH change spk (`OP_0 <20B>`).
    fn change_spk() -> ScriptBuf {
        let mut v = Vec::with_capacity(22);
        v.push(0x00); // OP_0
        v.push(0x14); // OP_PUSHBYTES_20
        v.extend_from_slice(&[0x22u8; 20]);
        ScriptBuf::from(v)
    }

    fn build_for(framed: &[u8]) -> Transaction {
        build_tx(
            framed,
            dummy_prevout(0),
            Amount::from_sat(10_000_000),
            &change_spk(),
            Amount::from_sat(1_000),
            Network::Regtest,
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_several_lengths() {
        for len in [0usize, 1, 2, 3, 16, 31, 32, 100] {
            let framed: Vec<u8> = (0..len).map(|i| (i * 5 + 9) as u8).collect();
            let tx = build_for(&framed);
            let back = decode(&tx).unwrap();
            assert_eq!(back, framed, "roundtrip failed for len {len}");
        }
    }

    #[test]
    fn length_rides_in_nsequence_and_version_is_one() {
        let framed: Vec<u8> = (0..20u32).map(|i| i as u8).collect();
        let tx = build_for(&framed);
        assert_eq!(tx.version, Version::ONE);
        assert_eq!(
            tx.input[0].sequence.to_consensus_u32() as usize,
            framed.len()
        );
        // 20 bytes -> 10 data outputs + 1 change.
        assert_eq!(tx.output.len(), 10 + 1);
    }

    #[test]
    fn built_tx_passes_bip110_validate() {
        let framed: Vec<u8> = (0..64u32).map(|i| (i % 251) as u8).collect();
        let tx = build_for(&framed);
        assert_eq!(
            crate::bip110::validate(&tx),
            Ok(()),
            "built field-value tx must be BIP-110 compliant"
        );
    }

    #[test]
    fn change_is_last_and_conserves_value() {
        let framed = b"hello".to_vec();
        let tx = build_for(&framed);
        let total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(
            total,
            10_000_000 - 1_000,
            "outputs + fee must equal prevout"
        );
    }

    #[test]
    fn fee_exceeding_value_errors() {
        let err = build_tx(
            &[0xff; 8],
            dummy_prevout(0),
            Amount::from_sat(500),
            &change_spk(),
            Amount::from_sat(1_000),
            Network::Regtest,
        );
        assert!(
            err.is_err(),
            "fee + data outputs > prevout value must error"
        );
    }
}
