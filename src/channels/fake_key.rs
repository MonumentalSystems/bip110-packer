//! Fake-key channel — **OUTPUT-ONLY**.
//!
//! Disguise `framed` bytes as "public keys" inside standard-looking Taproot
//! outputs. Each data output is a witness-v1 P2TR scriptPubKey `OP_1 <32 bytes>`
//! (exactly 34 bytes, satisfying the C1 cap) whose 32-byte "x-only pubkey" is in
//! fact raw payload data — NOT a real key, and with overwhelming probability not
//! a point anyone controls. The outputs are therefore **provably-in-practice
//! unspendable**.
//!
//! # Layout
//!
//! The `framed` bytes are prefixed with a 4-byte big-endian length and the result
//! is chunked into 32-byte words (the final word zero-padded). Each word becomes
//! one `OP_1 <32B>` output; the length prefix lets [`decode`] trim the padding.
//! A final change output pays `prevout_value - fee - dust` back to `change_to`.
//!
//! ```text
//! payload  = len_be_u32(framed) || framed        (then zero-padded to a 32-multiple)
//! output_i = OP_1 <payload[32*i .. 32*i+32]>       (34-byte scriptPubKey, C1 OK)
//! ```
//!
//! # Density / cost & permanence caveat
//!
//! This is the **worst** channel on every practical axis. The payload bytes are
//! **base** (non-witness) bytes billed at 4 weight units/byte, and — unlike an
//! `OP_RETURN` output, which nodes recognise as provably unspendable and drop
//! from the UTXO set — each fake-key output is an ordinary-looking P2TR UTXO that
//! every full node must retain in its UTXO set **forever** (it can never be
//! spent, because no one holds the "key"). Encoding data this way permanently
//! bloats the UTXO set: 32 payload bytes cost one perpetual UTXO entry plus its
//! dust value. Prefer any other channel unless you specifically need the data to
//! masquerade as spendable outputs.
//!
//! # BIP-110
//!
//! * **C1** — every fake-key scriptPubKey is exactly 34 bytes (`OP_1` + 32-byte
//!   push), the non-`OP_RETURN` output cap. This is the binding constraint and is
//!   what fixes the 32-byte-per-output capacity (see
//!   [`crate::channels::max_payload`]).
//! * **C1** — the change output is the caller's `change_to`, also `<= 34` bytes.
//! * The single input carries no witness, so the witness rules (C4–C9) are inert.

use anyhow::{anyhow, Result};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// Payload bytes carried by one fake-key output: a witness-v1 program is exactly
/// 32 bytes, so one `OP_1 <32B>` output carries 32 bytes (see
/// [`crate::channels::max_payload`], which reports `32`).
const WORD: usize = 32;

/// Per-data-output value. These outputs are (in practice) unspendable, so this is
/// pure UTXO-set bloat; it is set to a small dust amount for standardness realism.
const DUST_PER_OUTPUT: Amount = Amount::from_sat(330);

/// scriptPubKey byte 0 of a witness-v1 program: `OP_1` (a.k.a. `OP_PUSHNUM_1`).
const OP_1: u8 = 0x51;
/// scriptPubKey byte 1 of a 32-byte witness program: `OP_PUSHBYTES_32`.
const OP_PUSHBYTES_32: u8 = 0x20;

/// Build the 34-byte fake-key scriptPubKey `OP_1 <word>` for one 32-byte word.
fn fake_key_spk(word: &[u8; WORD]) -> ScriptBuf {
    let mut v = Vec::with_capacity(2 + WORD);
    v.push(OP_1);
    v.push(OP_PUSHBYTES_32);
    v.extend_from_slice(word);
    ScriptBuf::from(v)
}

/// Single transaction: spend `prevout`, emit the fake-key data outputs and a
/// change output to `change_to` worth `prevout_value - fee - dust`.
///
/// The `framed` payload is prefixed with its 4-byte big-endian length and chunked
/// into 32-byte words (last word zero-padded); each word becomes one 34-byte
/// `OP_1 <32B>` output. Because of the length prefix there is always at least one
/// data output, even for an empty `framed` payload.
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

    // Prefix a 4-byte big-endian length so `decode` can trim the zero padding of
    // the final 32-byte word back to the exact original payload.
    let len = u32::try_from(framed.len()).map_err(|_| {
        anyhow!(
            "payload {} bytes exceeds the 32-bit length prefix",
            framed.len()
        )
    })?;
    let mut payload = Vec::with_capacity(4 + framed.len());
    payload.extend_from_slice(&len.to_be_bytes());
    payload.extend_from_slice(framed);

    // One 34-byte `OP_1 <32B>` output per 32-byte word (final word zero-padded).
    let mut output: Vec<TxOut> = Vec::new();
    for chunk in payload.chunks(WORD) {
        let mut word = [0u8; WORD];
        word[..chunk.len()].copy_from_slice(chunk);
        output.push(TxOut {
            value: DUST_PER_OUTPUT,
            script_pubkey: fake_key_spk(&word),
        });
    }

    // Subtract the fee and the dust locked in the (unspendable) data outputs.
    let data_outputs = output.len() as u64;
    let dust_total = Amount::from_sat(DUST_PER_OUTPUT.to_sat() * data_outputs);
    let change_value = prevout_value
        .checked_sub(fee)
        .and_then(|v| v.checked_sub(dust_total))
        .ok_or_else(|| anyhow!("prevout {prevout_value} too small for fee {fee} + dust"))?;

    // Change output last; `decode` treats the final output as change.
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

/// Recover the **framed** bytes from the transaction's fake-key outputs.
///
/// Every output except the LAST (the change output) is treated as a fake-key data
/// output: its 32-byte witness program is appended, in output order. The leading
/// 4-byte big-endian length prefix is then read and used to trim the zero padding
/// of the final word.
pub fn decode(tx: &Transaction) -> Result<Vec<u8>> {
    let n = tx.output.len();
    if n < 2 {
        return Err(anyhow!(
            "fake-key tx must have at least one data output plus a change output (got {n})"
        ));
    }

    // All outputs except the last (change) carry data.
    let mut payload = Vec::with_capacity((n - 1) * WORD);
    for (i, txout) in tx.output[..n - 1].iter().enumerate() {
        let spk = &txout.script_pubkey;
        if !spk.is_p2tr() {
            return Err(anyhow!(
                "output {i} is not a fake-key (witness-v1 `OP_1 <32B>`) data output"
            ));
        }
        // A P2TR spk is exactly `OP_1 OP_PUSHBYTES_32 <32 bytes>`; the program is
        // the trailing 32 bytes.
        payload.extend_from_slice(&spk.as_bytes()[2..]);
    }

    if payload.len() < 4 {
        return Err(anyhow!(
            "fake-key payload {} bytes is too short for a 4-byte length prefix",
            payload.len()
        ));
    }
    let len = u32::from_be_bytes(payload[..4].try_into().expect("4-byte prefix")) as usize;
    let framed = &payload[4..];
    if len > framed.len() {
        return Err(anyhow!(
            "declared length {len} exceeds carried payload {} bytes",
            framed.len()
        ));
    }
    Ok(framed[..len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot_spend::dummy_prevout;

    /// A throwaway, C1-compliant 22-byte P2WPKH-shaped change spk (`OP_0 <20B>`).
    /// Deliberately NOT P2TR so it is visibly distinct from the data outputs.
    fn change_spk() -> ScriptBuf {
        let mut v = Vec::with_capacity(22);
        v.push(0x00); // OP_0 (witness v0)
        v.push(0x14); // OP_PUSHBYTES_20
        v.extend_from_slice(&[0x11u8; 20]);
        ScriptBuf::from(v)
    }

    fn build_for(framed: &[u8]) -> Transaction {
        build_tx(
            framed,
            dummy_prevout(0),
            Amount::from_sat(100_000),
            &change_spk(),
            Amount::from_sat(1_000),
            Network::Regtest,
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_several_lengths() {
        // Include non-multiples of 32 and multi-output payloads.
        for len in [0usize, 1, 28, 31, 32, 33, 64, 65, 100, 320] {
            let framed: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let tx = build_for(&framed);
            let back = decode(&tx).unwrap();
            assert_eq!(back, framed, "roundtrip failed for len {len}");
        }
    }

    #[test]
    fn every_data_output_spk_is_34_bytes_and_p2tr() {
        let framed: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let tx = build_for(&framed);
        let n = tx.output.len();
        for txout in &tx.output[..n - 1] {
            let spk = &txout.script_pubkey;
            assert_eq!(
                spk.len(),
                34,
                "fake-key data output spk must be 34 bytes (C1)"
            );
            assert!(spk.is_p2tr(), "fake-key data output must look like P2TR");
        }
        // 4-byte prefix + 100 bytes = 104 -> ceil(104/32) = 4 data outputs + change.
        assert_eq!(tx.output.len(), 4 + 1);
    }

    #[test]
    fn built_tx_passes_bip110_validate() {
        let framed: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let tx = build_tx(
            &framed,
            dummy_prevout(2),
            Amount::from_sat(50_000),
            &change_spk(),
            Amount::from_sat(500),
            Network::Regtest,
        )
        .unwrap();
        assert_eq!(
            crate::bip110::validate(&tx),
            Ok(()),
            "built fake-key tx must be BIP-110 compliant"
        );
    }

    #[test]
    fn change_output_is_last_and_pays_prevout_minus_fee_and_dust() {
        let framed: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
        let tx = build_for(&framed);
        // 4 + 64 = 68 -> ceil(68/32) = 3 data outputs, each 330 sat dust.
        let data_outputs = tx.output.len() - 1;
        assert_eq!(data_outputs, 3);
        let change = tx.output.last().expect("change output present");
        assert!(
            !change.script_pubkey.is_p2tr(),
            "last output is the change output"
        );
        let expected = Amount::from_sat(100_000 - 1_000 - 330 * data_outputs as u64);
        assert_eq!(change.value, expected);
    }

    #[test]
    fn fee_plus_dust_exceeding_value_errors() {
        let err = build_tx(
            b"\x00payload",
            dummy_prevout(0),
            Amount::from_sat(300),
            &change_spk(),
            Amount::from_sat(1_000),
            Network::Regtest,
        );
        assert!(err.is_err(), "fee + dust > prevout value must error");
    }
}
