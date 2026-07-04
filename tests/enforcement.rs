//! Enforcement battery: prove the independent `bip110::validate` checker REJECTS
//! each deliberate violation produced by the violation generator, and ACCEPTS a
//! compliant control. Uses only the public `bip110pack` API.

use bip110pack::bip110;
use bip110pack::taproot_spend::{build_spend_violation, commit_address, dummy_prevout};
use bip110pack::tapscript::{Auth, Violate};

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// A throwaway regtest destination scriptPubKey (a compliant 34-byte P2TR).
fn dest_spk() -> ScriptBuf {
    commit_address(b"enforcement-dest", Auth::None, Network::Regtest)
        .unwrap()
        .script_pubkey()
}

/// Build a violating reveal tx for the given leaf violation / output flag.
fn reveal(violate: Violate, oversize_output: bool) -> Transaction {
    let data: Vec<u8> = (0..1_000u32).map(|i| i as u8).collect();
    build_spend_violation(
        &data,
        violate,
        dummy_prevout(0),
        Amount::from_sat(100_000),
        &dest_spk(),
        Amount::from_sat(1_000),
        Network::Regtest,
        oversize_output,
    )
    .unwrap()
}

/// Assert `validate(tx)` fails with at least one violation of `rule`.
fn assert_rule(tx: &Transaction, rule: &str) {
    let err = bip110::validate(tx)
        .expect_err(&format!("expected a {rule} violation, but validate() passed"));
    assert!(
        err.iter().any(|v| v.rule == rule),
        "expected a {rule} violation; got {:?}",
        err
    );
}

#[test]
fn push_too_big_is_rejected_c3() {
    assert_rule(&reveal(Violate::PushTooBig, false), "C3");
}

#[test]
fn op_if_is_rejected_c8() {
    assert_rule(&reveal(Violate::OpIf, false), "C8");
}

#[test]
fn op_success_is_rejected_c7() {
    assert_rule(&reveal(Violate::OpSuccess, false), "C7");
}

#[test]
fn oversize_output_is_rejected_c1() {
    // Compliant leaf (Violate::None) + oversize non-OP_RETURN output → C1.
    assert_rule(&reveal(Violate::None, true), "C1");
}

#[test]
fn oversize_control_block_is_rejected_c6() {
    // Craft a witness whose last item is a well-formed-shape control block:
    // len = 33 + 32*8 = 289 (> 257) with a defined 0xc0 leaf-version first byte.
    // is_control_block() accepts the shape → treated as a script-path spend →
    // the 289-byte length trips C6.
    let mut cb = vec![0u8; 289];
    cb[0] = 0xc0;
    assert_eq!((cb.len() - 33) % 32, 0, "control block shape must be 33+32*m");

    // A trivially compliant tapleaf (OP_1) so only the control block trips a rule.
    let tapleaf = ScriptBuf::from(vec![0x51u8]); // OP_1

    let mut witness = Witness::new();
    witness.push(tapleaf.as_bytes());
    witness.push(cb.as_slice());

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: dummy_prevout(0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: dest_spk(),
        }],
    };

    assert_rule(&tx, "C6");
}

#[test]
fn compliant_control_passes() {
    // Violate::None, no oversize output: a normal spendable, compliant reveal.
    let tx = reveal(Violate::None, false);
    assert_eq!(
        bip110::validate(&tx),
        Ok(()),
        "compliant control must pass validation"
    );
}
