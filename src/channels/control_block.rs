//! Control-block channel — **COMMIT/REVEAL** (merkle-path smuggling).
//!
//! This channel hides data inside the *control block* of a Taproot script-path
//! spend. The tapleaf is a minimal, anyone-can-spend script (`OP_TRUE`), so it
//! carries no data itself; every data byte rides in fields of the control block
//! that consensus never constrains:
//!
//! * the 32-byte **internal key** `P` — 31 data bytes plus a 1-byte grind
//!   counter so the result is always a valid x-only point (`IK_DATA = 31`), and
//! * up to **7 merkle-path siblings** of 32 unconstrained data bytes each.
//!
//! # Layout of the embedded buffer
//!
//! The framed payload is prefixed with a single length byte and split across the
//! carriers, low bytes first:
//!
//! ```text
//! buffer = [len:u8] || framed || zero-padding
//!          \___ internal key P (buffer[0..31]) ___/\__ sibling_0 __/\__ … __/
//! ```
//!
//! `buffer[0..31]` becomes the first 31 bytes of `P` (byte 31 of `P` is the
//! grind counter); each following 32-byte window becomes one sibling. Decode
//! reverses this exactly: the length byte says how many payload bytes are real,
//! so the trailing zero-padding of the last sibling is discarded.
//!
//! # Capacity
//!
//! `31 + 7*32 - 1 = 254` framed bytes per input. At the maximum the control
//! block is `33 + 7*32 = 257` bytes — exactly the BIP-110 C6 limit. (The
//! foundation advertises a conservative `224` in [`crate::channels::max_payload`],
//! which counts only the seven sibling slots; this module additionally uses the
//! internal key, so it can carry a little more.)
//!
//! # Ordering / the BIP341 sort
//!
//! BIP341 sorts each `(node, sibling)` pair lexicographically before hashing a
//! `TapBranch`. That sort only affects *how the merkle root is computed*, never
//! the order siblings are stored in the serialized control block: they are laid
//! out leaf-to-root and read back in that same order. Decode therefore reads the
//! raw 32-byte sibling windows verbatim and the round-trip is unambiguous — the
//! sort is irrelevant to decoding. [`crate::taproot_spend`] uses the identical
//! fold ([`TapNodeHash::from_node_hashes`], which performs the sort), so
//! [`ControlBlock::verify_taproot_commitment`] on the reveal succeeds.

use anyhow::{anyhow, ensure, Result};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, TapTweak};
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapNodeHash};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// Data bytes carried in the internal key: 32 minus a 1-byte grind counter.
const IK_DATA: usize = 31;
/// Maximum number of 32-byte merkle siblings (C6: `33 + 7*32 = 257`).
const MAX_SIBLINGS: usize = 7;
/// Framed-byte capacity: `31 + 7*32` carrier bytes minus the 1-byte length
/// prefix = `254`.
const MAX_PAYLOAD: usize = IK_DATA + MAX_SIBLINGS * 32 - 1;

/// A reproducible control-block commitment for a framed payload.
struct Commitment {
    /// The minimal anyone-can-spend tapleaf (`OP_TRUE`).
    script: ScriptBuf,
    /// The serialized control block: `[leaf|parity][P][sibling…]`.
    control_block: Vec<u8>,
    /// The data-derived internal key `P`.
    internal_key: XOnlyPublicKey,
    /// The folded merkle root (leaf hash folded with every sibling).
    merkle_root: TapNodeHash,
}

/// Land on a valid x-only internal key that carries `data` (`<= IK_DATA` bytes)
/// in its first 31 bytes, grinding byte 31 until the 32 bytes are a valid point.
///
/// About half of all 32-byte strings are valid x-coordinates, so a match is
/// essentially always found within the 256 candidate values.
fn grind_internal_key(data: &[u8]) -> Result<XOnlyPublicKey> {
    debug_assert!(data.len() <= IK_DATA);
    let mut buf = [0u8; 32];
    buf[..data.len()].copy_from_slice(data);
    for g in 0u8..=u8::MAX {
        buf[IK_DATA] = g; // byte 31 is the grind counter, excluded from decode
        if let Ok(pk) = XOnlyPublicKey::from_slice(&buf) {
            return Ok(pk);
        }
    }
    Err(anyhow!("failed to grind a valid x-only internal key"))
}

/// Build the deterministic control-block commitment for `framed`.
///
/// Reproducible from `framed` alone (the grind is deterministic), so
/// [`commit_address`] and [`build_reveal`] agree. Verifies the resulting control
/// block actually commits to the minimal leaf before returning.
fn commitment(framed: &[u8]) -> Result<Commitment> {
    ensure!(
        framed.len() <= MAX_PAYLOAD,
        "control-block payload {} bytes exceeds capacity {MAX_PAYLOAD}",
        framed.len()
    );

    // buffer = [len:u8] || framed
    let mut buf = Vec::with_capacity(1 + framed.len());
    buf.push(framed.len() as u8);
    buf.extend_from_slice(framed);

    // Internal key carries the first IK_DATA bytes; each sibling carries 32.
    let ik_data = &buf[..buf.len().min(IK_DATA)];
    let internal_key = grind_internal_key(ik_data)?;

    let mut siblings: Vec<[u8; 32]> = Vec::new();
    if buf.len() > IK_DATA {
        for chunk in buf[IK_DATA..].chunks(32) {
            let mut sib = [0u8; 32];
            sib[..chunk.len()].copy_from_slice(chunk);
            siblings.push(sib);
        }
    }
    debug_assert!(siblings.len() <= MAX_SIBLINGS);

    // Minimal anyone-can-spend tapleaf: a single OP_TRUE (0x51). No OP_IF /
    // OP_NOTIF (C8) and no OP_SUCCESS (C7); it leaves exactly `[1]` on the stack.
    let script = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();

    // Fold the leaf node hash with each sibling exactly as BIP341 does (the
    // combiner sorts each pair), yielding the merkle root.
    let mut node = TapNodeHash::from_script(&script, LeafVersion::TapScript);
    for sib in &siblings {
        let sib_node = TapNodeHash::from_byte_array(*sib);
        node = TapNodeHash::from_node_hashes(node, sib_node);
    }
    let merkle_root = node;

    // Tweak the internal key by the root to obtain the output key + its parity.
    let secp = Secp256k1::new();
    let (output_key, parity) = internal_key.tap_tweak(&secp, Some(merkle_root));

    // Serialize the control block: [leaf_version | parity][P][sibling_0..k].
    let mut control_block = Vec::with_capacity(33 + siblings.len() * 32);
    control_block.push(LeafVersion::TapScript.to_consensus() | parity.to_u8());
    control_block.extend_from_slice(&internal_key.serialize());
    for sib in &siblings {
        control_block.extend_from_slice(sib);
    }

    // The reveal MUST actually validate: the control block has to commit to the
    // minimal leaf under the derived output key.
    let decoded =
        ControlBlock::decode(&control_block).map_err(|e| anyhow!("control block decode: {e}"))?;
    ensure!(
        decoded.verify_taproot_commitment(&secp, output_key.to_x_only_public_key(), &script),
        "internal error: control block does not commit to the minimal leaf"
    );

    Ok(Commitment {
        script,
        control_block,
        internal_key,
        merkle_root,
    })
}

/// P2TR commit address whose (later revealed) control block will carry `framed`.
pub fn commit_address(framed: &[u8], network: Network) -> Result<Address> {
    let c = commitment(framed)?;
    let secp = Secp256k1::new();
    Ok(Address::p2tr(
        &secp,
        c.internal_key,
        Some(c.merkle_root),
        network,
    ))
}

/// Reveal transaction that spends `prevout` and carries `framed` in its control
/// block, paying `prevout_value - fee` to `to`.
///
/// The witness is `[minimal_script, control_block]` — an anyone-can-spend
/// script-path spend, no signature required.
pub fn build_reveal(
    framed: &[u8],
    prevout: OutPoint,
    prevout_value: Amount,
    to: &ScriptBuf,
    fee: Amount,
    network: Network,
) -> Result<Transaction> {
    // The raw tx is network-agnostic; `network` matters only to address
    // derivation (which the commit step already did).
    let _ = network;

    let c = commitment(framed)?;

    let out_value = prevout_value
        .checked_sub(fee)
        .ok_or_else(|| anyhow!("fee {fee} exceeds prevout value {prevout_value}"))?;

    let mut witness = Witness::new();
    witness.push(c.script.as_bytes());
    witness.push(c.control_block.as_slice());

    let txin = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness,
    };
    let txout = TxOut {
        value: out_value,
        script_pubkey: to.clone(),
    };

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    })
}

/// Recover the **framed** bytes from a control-block reveal transaction.
///
/// Reads the control block (the last witness item of the first input), takes the
/// first 31 bytes of the internal key plus every 32-byte sibling to rebuild the
/// embedded buffer, then trims it to the length recorded in the leading byte.
pub fn decode(tx: &Transaction) -> Result<Vec<u8>> {
    let witness = &tx
        .input
        .first()
        .ok_or_else(|| anyhow!("tx has no inputs"))?
        .witness;
    let cb = witness
        .last()
        .ok_or_else(|| anyhow!("input witness is empty; expected a control block"))?;

    ensure!(
        cb.len() >= 33,
        "control block too short: {} bytes",
        cb.len()
    );
    ensure!(
        (cb.len() - 33).is_multiple_of(32),
        "control block length {} is not 33 + 32*m",
        cb.len()
    );

    // Rebuild the embedded buffer: internal-key data bytes (skip the grind byte
    // at index 32) followed by the raw sibling windows.
    let mut buf = Vec::with_capacity(IK_DATA + (cb.len() - 33));
    buf.extend_from_slice(&cb[1..1 + IK_DATA]);
    buf.extend_from_slice(&cb[33..]);

    let len = *buf
        .first()
        .ok_or_else(|| anyhow!("empty control-block buffer"))? as usize;
    ensure!(
        len < buf.len(),
        "declared payload length {len} exceeds {} available bytes",
        buf.len() - 1
    );
    Ok(buf[1..1 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot_spend::dummy_prevout;

    fn dest_spk() -> ScriptBuf {
        // A throwaway 34-byte P2TR destination (<= 34 bytes, so C1-clean).
        commit_address(b"throwaway destination", Network::Regtest)
            .unwrap()
            .script_pubkey()
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
            .collect()
    }

    #[test]
    fn roundtrip_various_sizes_up_to_cap() {
        let to = dest_spk();
        for len in [
            0usize,
            1,
            2,
            30,
            31,
            32,
            33,
            63,
            64,
            100,
            200,
            224,
            MAX_PAYLOAD,
        ] {
            let framed = sample(len);
            let tx = build_reveal(
                &framed,
                dummy_prevout(0),
                Amount::from_sat(100_000),
                &to,
                Amount::from_sat(1_000),
                Network::Regtest,
            )
            .unwrap();
            let recovered = decode(&tx).unwrap();
            assert_eq!(recovered, framed, "round-trip failed for len {len}");
        }
    }

    #[test]
    fn built_tx_is_bip110_compliant() {
        let to = dest_spk();
        for len in [0usize, 1, 100, 224, MAX_PAYLOAD] {
            let framed = sample(len);
            let tx = build_reveal(
                &framed,
                dummy_prevout(1),
                Amount::from_sat(100_000),
                &to,
                Amount::from_sat(1_000),
                Network::Regtest,
            )
            .unwrap();
            assert_eq!(
                crate::bip110::validate(&tx),
                Ok(()),
                "reveal for len {len} must be BIP-110 compliant"
            );
            // One 34-byte P2TR output, value == prevout - fee.
            assert_eq!(tx.output.len(), 1);
            assert_eq!(tx.output[0].script_pubkey.len(), 34);
            assert_eq!(tx.output[0].value, Amount::from_sat(99_000));
        }
    }

    #[test]
    fn control_block_verifies_and_stays_within_c6() {
        let secp = Secp256k1::new();
        for len in [0usize, 31, 224, MAX_PAYLOAD] {
            let c = commitment(&sample(len)).unwrap();
            assert!(
                c.control_block.len() <= 257,
                "control block {} bytes exceeds C6 (257) for len {len}",
                c.control_block.len()
            );
            let cb = ControlBlock::decode(&c.control_block).unwrap();
            let (output_key, _) = c.internal_key.tap_tweak(&secp, Some(c.merkle_root));
            assert!(
                cb.verify_taproot_commitment(&secp, output_key.to_x_only_public_key(), &c.script),
                "control block must commit to the minimal leaf for len {len}"
            );
        }
    }

    #[test]
    fn max_payload_control_block_is_exactly_257() {
        let c = commitment(&sample(MAX_PAYLOAD)).unwrap();
        assert_eq!(c.control_block.len(), 257);
    }

    #[test]
    fn commit_address_is_deterministic() {
        let a = commit_address(&sample(64), Network::Regtest).unwrap();
        let b = commit_address(&sample(64), Network::Regtest).unwrap();
        assert_eq!(
            a, b,
            "commit address must be reproducible from framed bytes"
        );
    }

    #[test]
    fn over_capacity_is_rejected() {
        let framed = vec![0u8; MAX_PAYLOAD + 1];
        assert!(
            build_reveal(
                &framed,
                dummy_prevout(0),
                Amount::from_sat(10_000),
                &dest_spk(),
                Amount::from_sat(0),
                Network::Regtest,
            )
            .is_err(),
            "payloads beyond the 254-byte cap must be rejected"
        );
    }
}
