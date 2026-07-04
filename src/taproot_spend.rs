//! Taproot output construction + script-path spend with a **deterministic**
//! internal key (fixed bytes, no RNG).

use anyhow::{anyhow, Result};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, Secp256k1, UntweakedPublicKey};
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::{All, Message, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use crate::tapscript::{build_tapscript, build_tapscript_auth, Auth};

/// Fixed 32-byte secret used to derive the deterministic internal key.
/// Any value in `[1, n-1]` works; `0x01` repeated is trivially valid.
pub const INTERNAL_KEY_SECRET: [u8; 32] = [0x01u8; 32];

/// Fixed 32-byte secret used to derive the deterministic **reveal** keypair for
/// [`Auth::Checksig`] spends. Distinct from [`INTERNAL_KEY_SECRET`].
pub const REVEAL_KEY_SECRET: [u8; 32] = [0x02u8; 32];

/// Derive the deterministic (no-RNG) untweaked internal key.
pub fn internal_key(secp: &Secp256k1<All>) -> UntweakedPublicKey {
    let sk = SecretKey::from_slice(&INTERNAL_KEY_SECRET).expect("secret in range");
    let kp = Keypair::from_secret_key(secp, &sk);
    kp.x_only_public_key().0
}

/// Derive the deterministic (no-RNG) reveal keypair used to sign
/// [`Auth::Checksig`] script-path spends.
pub fn reveal_keypair(secp: &Secp256k1<All>) -> Keypair {
    let sk = SecretKey::from_slice(&REVEAL_KEY_SECRET).expect("reveal secret in range");
    Keypair::from_secret_key(secp, &sk)
}

/// Everything needed to build and spend a single-leaf Taproot output.
pub struct SpendBundle {
    /// The data-carrying tapleaf script.
    pub script: ScriptBuf,
    /// Control block for the script-path spend (33 bytes for a single leaf).
    pub control_block: ControlBlock,
    /// The P2TR `scriptPubKey` (exactly 34 bytes).
    pub spk: ScriptBuf,
    /// Full Taproot spend info (output key, merkle root, …).
    pub spend_info: TaprootSpendInfo,
}

/// Build the Taproot commitment (single leaf, depth 0) for the given data blob.
pub fn build_spend(data: &[u8]) -> Result<SpendBundle> {
    let secp = Secp256k1::new();
    let ik = internal_key(&secp);
    let script = build_tapscript(data);

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .map_err(|e| anyhow!("add_leaf: {e:?}"))?
        .finalize(&secp, ik)
        .map_err(|_| anyhow!("incomplete taproot tree"))?;

    let control_block = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| anyhow!("script not present in tree"))?;

    let spk = ScriptBuf::new_p2tr(&secp, ik, spend_info.merkle_root());

    Ok(SpendBundle {
        script,
        control_block,
        spk,
        spend_info,
    })
}

/// Build the Taproot commitment for `data` using an explicit [`Auth`] mode.
///
/// Identical to [`build_spend`] but the tapleaf is the ord-compatible envelope
/// produced by [`build_tapscript_auth`].
pub fn build_spend_auth(data: &[u8], auth: Auth) -> Result<SpendBundle> {
    let secp = Secp256k1::new();
    let ik = internal_key(&secp);
    let script = build_tapscript_auth(data, auth);

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .map_err(|e| anyhow!("add_leaf: {e:?}"))?
        .finalize(&secp, ik)
        .map_err(|_| anyhow!("incomplete taproot tree"))?;

    let control_block = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| anyhow!("script not present in tree"))?;

    let spk = ScriptBuf::new_p2tr(&secp, ik, spend_info.merkle_root());

    Ok(SpendBundle {
        script,
        control_block,
        spk,
        spend_info,
    })
}

/// Compute the P2TR address to fund so its single-leaf tapleaf can later be
/// revealed as a `data`-carrying script-path spend under `auth`.
pub fn commit_address(data: &[u8], auth: Auth, network: Network) -> Result<Address> {
    let secp = Secp256k1::new();
    let ik = internal_key(&secp);
    let bundle = build_spend_auth(data, auth)?;
    Ok(Address::p2tr(
        &secp,
        ik,
        bundle.spend_info.merkle_root(),
        network,
    ))
}

/// Build a fully-formed 1-in/1-out transaction that reveals `data` by
/// script-path-spending `prevout` (value `prevout_value`) and pays
/// `prevout_value - fee` to `to`.
///
/// For [`Auth::Checksig`] the BIP341 taproot **script-path** sighash
/// (`SIGHASH_DEFAULT`) is computed and Schnorr-signed with the deterministic
/// reveal keypair; the 64-byte signature is the first witness item. For
/// [`Auth::None`] the witness is just `[script, control_block]`.
pub fn build_signed_spend(
    data: &[u8],
    auth: Auth,
    prevout: OutPoint,
    prevout_value: Amount,
    to: &ScriptBuf,
    fee: Amount,
    network: Network,
) -> Result<Transaction> {
    // `network` participates only in address derivation elsewhere; the raw tx is
    // network-agnostic. Touch it so the signature is honoured and consistent.
    let _ = commit_address(data, auth, network)?;

    let bundle = build_spend_auth(data, auth)?;

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

    let mut witness = Witness::new();
    match auth {
        Auth::None => {
            witness.push(bundle.script.as_bytes());
            witness.push(bundle.control_block.serialize());
        }
        Auth::Checksig => {
            let secp = Secp256k1::new();
            let leaf_hash = TapLeafHash::from_script(&bundle.script, LeafVersion::TapScript);
            let prevout_txout = TxOut {
                value: prevout_value,
                script_pubkey: bundle.spk.clone(),
            };
            let sighash = {
                let mut cache = SighashCache::new(&tx);
                cache
                    .taproot_script_spend_signature_hash(
                        0,
                        &Prevouts::All(&[prevout_txout]),
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .map_err(|e| anyhow!("taproot sighash: {e}"))?
            };
            let msg = Message::from_digest(sighash.to_byte_array());
            let kp = reveal_keypair(&secp);
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
            witness.push(sig.serialize());
            witness.push(bundle.script.as_bytes());
            witness.push(bundle.control_block.serialize());
        }
    }
    tx.input[0].witness = witness;

    Ok(tx)
}

/// A deterministic, distinct dummy previous-output txid for tx index `i`.
///
/// In a real self-mined block these would be genuine post-activation P2TR UTXOs
/// (grandfathering rule C10). For packing/weight/validation purposes any
/// distinct 36-byte outpoint suffices.
pub fn dummy_prevout(i: u32) -> OutPoint {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&i.to_le_bytes());
    bytes[31] = 0xA5; // avoid the all-zero (coinbase-null) txid
    OutPoint {
        txid: Txid::from_byte_array(bytes),
        vout: 0,
    }
}

/// Build a complete data-carrying transaction: one input (script-path spend of
/// the single-leaf tapleaf) and one 34-byte P2TR output.
pub fn build_tx(data: &[u8], prevout: OutPoint) -> Result<Transaction> {
    let bundle = build_spend(data)?;

    // Witness stack (exactly two items): [ <tapscript> , <control block> ].
    // The control block is last, and its first byte is 0xc0/0xc1 (never 0x50),
    // so this stack can never be misread as carrying an annex.
    let mut witness = Witness::new();
    witness.push(bundle.script.as_bytes());
    witness.push(bundle.control_block.serialize());

    let txin = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness,
    };

    let txout = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: bundle.spk,
    };

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_block_at_most_257_bytes() {
        let bundle = build_spend(b"some data here").unwrap();
        let cb = bundle.control_block.serialize();
        assert_eq!(cb.len(), 33, "single-leaf control block is 33 bytes");
        assert!(cb.len() <= 257);
        // leaf version | parity, masked with 0xfe == 0xc0 (TapScript).
        assert_eq!(cb[0] & 0xfe, 0xc0);
    }

    #[test]
    fn output_spk_is_exactly_34_bytes() {
        let bundle = build_spend(b"payload").unwrap();
        assert_eq!(bundle.spk.len(), 34);
        assert_eq!(bundle.spk.as_bytes()[0], 0x51); // OP_1 / witness v1
    }

    #[test]
    fn control_block_verifies_commitment() {
        let secp = Secp256k1::new();
        let bundle = build_spend(b"verify me").unwrap();
        let ok = bundle.control_block.verify_taproot_commitment(
            &secp,
            bundle.spend_info.output_key().to_x_only_public_key(),
            &bundle.script,
        );
        assert!(ok, "control block must commit to the tapleaf");
    }
}
