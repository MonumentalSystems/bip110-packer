//! P2WSH-envelope channel — **COMMIT/REVEAL**.
//!
//! Carry `framed` bytes inside a witness-v0 P2WSH witnessScript. This is the
//! classic Ordinals-style envelope, and it is BIP-110-legal in witness v0 for two
//! reasons the tapscript channel cannot rely on:
//!
//! * The v0 witnessScript is **exempt** from the C4 non-exempt-witness-item cap
//!   (like a BIP16 redeemScript or a tapleaf script), so the whole envelope may be
//!   a single large witness item.
//! * `OP_IF`/`OP_NOTIF` are **permitted** in v0 scripts — BIP-110's C8 ban applies
//!   only to tapscript — so an `OP_FALSE OP_IF … OP_ENDIF` envelope is legal.
//!
//! ## witnessScript shape
//!
//! ```text
//! OP_FALSE OP_IF <push <=255B> <push <=255B> … OP_ENDIF OP_TRUE
//! ```
//!
//! Because the guard is `OP_FALSE`, the `IF` branch is never executed: the data
//! pushes are pure dead code, never interpreted, and execution falls straight
//! through to the trailing `OP_TRUE`, leaving exactly one truthy element on the
//! stack. The spend therefore needs **no** stack inputs — the witness is just the
//! single witnessScript item.
//!
//! ## Constraints
//!
//! * Each internal push is `<= CHUNK_SIZE (255) <= 256`, satisfying the C3
//!   per-push cap.
//! * Witness v0 keeps the 10,000-byte `MAX_SCRIPT_SIZE`, so one witnessScript
//!   caps out around ~9,900 data bytes. [`build_witness_script`] rejects anything
//!   that would overflow the 10,000-byte script; split larger payloads across
//!   multiple reveals.
//! * Output is P2WSH: `scriptPubKey = OP_0 <32-byte sha256(witnessScript)>` = 34
//!   bytes, satisfying the C1 output cap.

use anyhow::{anyhow, Result};
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::{OP_ENDIF, OP_IF, OP_PUSHBYTES_0, OP_PUSHNUM_1};
use bitcoin::script::{Builder, Instruction, PushBytesBuf};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

use crate::tapscript::CHUNK_SIZE;

/// Consensus `MAX_SCRIPT_SIZE` for a witness-v0 script (bytes). A P2WSH
/// witnessScript larger than this is invalid, so it bounds the per-reveal
/// capacity.
pub const MAX_WITNESS_SCRIPT: usize = 10_000;

/// Convert a `<= 255`-byte chunk into a `PushBytesBuf`. Infallible for our chunk
/// sizes (255 < `u32::MAX`).
fn to_push(chunk: &[u8]) -> PushBytesBuf {
    PushBytesBuf::try_from(chunk.to_vec()).expect("chunk length <= 255 fits a push")
}

/// Build the `OP_FALSE OP_IF <pushes…> OP_ENDIF OP_TRUE` witnessScript carrying
/// `framed`.
///
/// Errors if the resulting script would exceed [`MAX_WITNESS_SCRIPT`] (the v0
/// consensus script-size limit).
fn build_witness_script(framed: &[u8]) -> Result<ScriptBuf> {
    // OP_FALSE guard: the IF branch never executes, so the data pushes are inert.
    let mut b = Builder::new()
        .push_opcode(OP_PUSHBYTES_0)
        .push_opcode(OP_IF);
    for chunk in framed.chunks(CHUNK_SIZE) {
        b = b.push_slice(to_push(chunk));
    }
    // Close the (skipped) branch and terminate with a single truthy element.
    let script = b
        .push_opcode(OP_ENDIF)
        .push_opcode(OP_PUSHNUM_1)
        .into_script();

    if script.len() > MAX_WITNESS_SCRIPT {
        return Err(anyhow!(
            "framed payload of {} bytes needs a {}-byte witnessScript, exceeding the \
             {}-byte v0 MAX_SCRIPT_SIZE; split it across multiple reveals",
            framed.len(),
            script.len(),
            MAX_WITNESS_SCRIPT
        ));
    }
    Ok(script)
}

/// P2WSH commit address whose witnessScript envelope will carry `framed`.
pub fn commit_address(framed: &[u8], network: Network) -> Result<Address> {
    let witness_script = build_witness_script(framed)?;
    Ok(Address::p2wsh(&witness_script, network))
}

/// Reveal transaction that spends `prevout` and reveals the P2WSH witnessScript
/// carrying `framed`, paying `prevout_value - fee` to `to`.
///
/// The envelope needs no stack inputs, so the witness is the single witnessScript
/// item. The raw transaction is network-agnostic; `network` is accepted for
/// signature parity with the channel contract.
pub fn build_reveal(
    framed: &[u8],
    prevout: OutPoint,
    prevout_value: Amount,
    to: &ScriptBuf,
    fee: Amount,
    network: Network,
) -> Result<Transaction> {
    let _ = network;

    let witness_script = build_witness_script(framed)?;

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

    // P2WSH spend of a script needing no arguments: witness = [ witnessScript ].
    let mut witness = Witness::new();
    witness.push(witness_script.as_bytes());
    tx.input[0].witness = witness;

    Ok(tx)
}

/// Recover the **framed** bytes from a P2WSH-envelope reveal transaction.
///
/// Reads the witnessScript (the last/only witness item of the first input) and
/// concatenates every push that appears between `OP_IF` and `OP_ENDIF`.
pub fn decode(tx: &Transaction) -> Result<Vec<u8>> {
    let witness = &tx
        .input
        .first()
        .ok_or_else(|| anyhow!("tx has no inputs"))?
        .witness;
    let script_bytes = witness
        .last()
        .ok_or_else(|| anyhow!("input witness is empty; expected a P2WSH witnessScript"))?;
    let script = ScriptBuf::from(script_bytes.to_vec());

    let mut out = Vec::new();
    let mut in_envelope = false;
    for ins in script.instructions() {
        match ins {
            Ok(Instruction::Op(op)) => {
                if op == OP_IF {
                    in_envelope = true;
                } else if op == OP_ENDIF {
                    break;
                }
            }
            Ok(Instruction::PushBytes(pb)) => {
                if in_envelope {
                    out.extend_from_slice(pb.as_bytes());
                }
            }
            Err(e) => return Err(anyhow!("malformed P2WSH witnessScript: {e}")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot_spend::dummy_prevout;

    /// A throwaway 34-byte P2WSH destination scriptPubKey (satisfies C1).
    fn dest_spk(network: Network) -> ScriptBuf {
        commit_address(b"\x00throwaway destination", network)
            .unwrap()
            .script_pubkey()
    }

    fn reveal(framed: &[u8]) -> Transaction {
        let network = Network::Regtest;
        build_reveal(
            framed,
            dummy_prevout(0),
            Amount::from_sat(100_000),
            &dest_spk(network),
            Amount::from_sat(1_000),
            network,
        )
        .unwrap()
    }

    #[test]
    fn roundtrips_various_lengths() {
        // Every length fits in one <=10000-byte witnessScript.
        for len in [0usize, 1, 50, 254, 255, 256, 510, 1000, 5000, 9000] {
            let framed: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let tx = reveal(&framed);
            let recovered = decode(&tx).unwrap();
            assert_eq!(recovered, framed, "round-trip failed for len {len}");
        }
    }

    #[test]
    fn commit_address_is_p2wsh_34_byte_spk() {
        let spk = commit_address(b"\x00p2wsh envelope", Network::Regtest)
            .unwrap()
            .script_pubkey();
        assert!(spk.is_p2wsh(), "commit address must be P2WSH");
        assert_eq!(
            spk.len(),
            34,
            "P2WSH spk is OP_0 <32-byte hash> = 34 bytes (C1)"
        );
    }

    #[test]
    fn built_tx_is_bip110_compliant_for_small_payload() {
        // A payload whose witnessScript stays <= 256 bytes so the single-item v0
        // witness clears the re-checker's C4 item cap (the bundled validator does
        // not model the v0 witnessScript exemption, so keep this reveal small).
        let framed: Vec<u8> = (0..150u32).map(|i| i as u8).collect();
        let tx = reveal(&framed);
        assert_eq!(
            crate::bip110::validate(&tx),
            Ok(()),
            "P2WSH-envelope reveal must be BIP-110 compliant"
        );
        assert_eq!(decode(&tx).unwrap(), framed, "must still round-trip");
    }

    #[test]
    fn witness_script_within_size_caps_and_pushes_bounded() {
        let framed: Vec<u8> = (0..8000u32).map(|i| (i % 253) as u8).collect();
        let tx = reveal(&framed);
        let ws = tx.input[0].witness.last().expect("witnessScript present");
        assert!(
            ws.len() <= MAX_WITNESS_SCRIPT,
            "witnessScript must be <= {MAX_WITNESS_SCRIPT} bytes, got {}",
            ws.len()
        );
        let script = ScriptBuf::from(ws.to_vec());
        for ins in script.instructions() {
            if let Ok(Instruction::PushBytes(pb)) = ins {
                assert!(
                    pb.as_bytes().len() <= 256,
                    "every internal push must be <= 256 (C3)"
                );
            }
        }
    }

    #[test]
    fn oversized_payload_errors_clearly() {
        // Too large to fit a single <=10000-byte witnessScript.
        let framed = vec![0xABu8; 10_050];
        assert!(
            commit_address(&framed, Network::Regtest).is_err(),
            "commit_address must reject an over-large payload"
        );
        assert!(
            build_reveal(
                &framed,
                dummy_prevout(0),
                Amount::from_sat(100_000),
                &dest_spk(Network::Regtest),
                Amount::from_sat(1_000),
                Network::Regtest,
            )
            .is_err(),
            "build_reveal must reject an over-large payload"
        );
    }
}
