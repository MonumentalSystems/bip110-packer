//! Independent BIP-110 compliance re-checker.
//!
//! This module does **not** trust the generator: it re-derives every check from
//! the raw transaction (outputs, witness stacks, tapscript opcode stream,
//! control block) and reports any violation. See the checklist in the crate
//! docs (C1–C10).
//!
//! Note on prevout-dependent rules: a bare `Transaction` does not carry its
//! spent `scriptPubKey`s, so the "spends a witness-v1 output" half of C9 and the
//! grandfathering rule C10 cannot be checked from the tx alone. What *can* be
//! checked from the witness — the tapleaf/control-block **leaf version** being
//! the defined `0xc0` TapScript version — is enforced here (C9b).

use bitcoin::script::{Instruction, ScriptBuf};
use bitcoin::Transaction;

/// Maximum non-OP_RETURN output scriptPubKey size (bytes).
pub const MAX_SPK: usize = 34;
/// Maximum OP_RETURN output scriptPubKey size (bytes).
pub const MAX_OP_RETURN_SPK: usize = 83;
/// Maximum OP_PUSHDATA payload / non-exempt witness item size (bytes).
pub const MAX_PUSH: usize = 256;
/// Maximum Taproot control block size (bytes).
pub const MAX_CONTROL_BLOCK: usize = 257;

const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const ANNEX_TAG: u8 = 0x50;

/// A single BIP-110 rule violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Rule identifier from the audit checklist (e.g. "C1", "C7").
    pub rule: &'static str,
    /// Human-readable description of what failed.
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.rule, self.detail)
    }
}

/// Is `item` a well-formed Taproot control block: length `33 + 32*m` for some
/// `m >= 0` and a defined leaf-version/parity first byte (`first & 0xfe == 0xc0`)?
///
/// Only when the LAST witness item satisfies this do we treat the spend as a
/// taproot script-path spend (exempting the second-to-last item, the tapleaf
/// script, from the per-item size cap). Otherwise every item is a plain
/// script-argument witness item subject to the 256-byte cap.
fn is_control_block(item: &[u8]) -> bool {
    item.len() >= 33 && (item.len() - 33).is_multiple_of(32) && (item[0] & 0xfe) == 0xc0
}

/// Is `b` an `OP_SUCCESSx` opcode byte (per BIP342)?
///
/// Set: 80, 98, 126–129, 131–134, 137–138, 141–142, 149–153, 187–254.
pub fn is_op_success(b: u8) -> bool {
    b == 80
        || b == 98
        || (126..=129).contains(&b)
        || (131..=134).contains(&b)
        || (137..=138).contains(&b)
        || (141..=142).contains(&b)
        || (149..=153).contains(&b)
        || (187..=254).contains(&b)
}

/// Re-check a single tapscript against the opcode-level BIP-110 rules
/// (C3 per-push cap, C7 no OP_SUCCESS, C8 no OP_IF/OP_NOTIF).
fn check_tapscript(script: &ScriptBuf, out: &mut Vec<Violation>) {
    // Iterating instructions parses pushdata correctly, so bytes *inside* a
    // pushed payload (which may legally be 0x63, 0x50, …) are never mistaken for
    // opcodes.
    for ins in script.instructions() {
        match ins {
            Ok(Instruction::PushBytes(pb)) => {
                let n = pb.as_bytes().len();
                if n > MAX_PUSH {
                    out.push(Violation {
                        rule: "C3",
                        detail: format!("tapscript push payload {n} bytes > {MAX_PUSH}"),
                    });
                }
            }
            Ok(Instruction::Op(op)) => {
                let b = op.to_u8();
                if b == OP_IF || b == OP_NOTIF {
                    // C8: BIP-110 bans the *execution* of OP_IF/OP_NOTIF, which
                    // cannot be determined from bytes alone. Flagging their mere
                    // presence is a conservative over-approximation: it may
                    // reject a script whose OP_IF branch is never executed, but
                    // never accepts one that would execute it.
                    out.push(Violation {
                        rule: "C8",
                        detail: format!("tapscript contains OP_IF/OP_NOTIF (0x{b:02x})"),
                    });
                }
                if is_op_success(b) {
                    out.push(Violation {
                        rule: "C7",
                        detail: format!("tapscript contains OP_SUCCESS opcode 0x{b:02x}"),
                    });
                }
            }
            Err(e) => {
                out.push(Violation {
                    rule: "C7",
                    detail: format!("malformed tapscript: {e}"),
                });
                break;
            }
        }
    }
}

/// Re-check one input's witness stack (C4 item cap, C5 annex, C6 control block
/// size, C7/C8 tapscript, C9b leaf version).
fn check_witness(input_idx: usize, items: &[&[u8]], out: &mut Vec<Violation>) {
    if items.is_empty() {
        // No witness: not a segwit spend we produced. Nothing witness-specific
        // to check here.
        return;
    }

    // C5: annex forbidden. An annex is present iff stack has >= 2 items and the
    // last item's first byte is 0x50.
    if items.len() >= 2 {
        if let Some(last) = items.last() {
            if last.first() == Some(&ANNEX_TAG) {
                out.push(Violation {
                    rule: "C5",
                    detail: format!("input {input_idx}: witness carries an annex (0x50)"),
                });
                // Continue checking the rest; annex stripping semantics don't
                // matter because the tx is already invalid.
            }
        }
    }

    // A spend is a Taproot script-path spend only when the LAST witness item is a
    // *well-formed* control block (`33 + 32*m` bytes and a `0xc0`/`0xc1` leaf
    // version byte). Only then is the second-to-last item the exempt tapleaf
    // script. If the last item is NOT a valid control block, treat every item as
    // a plain, non-exempt script-argument witness item subject to the 256B cap.
    let last = items[items.len() - 1];
    let is_script_path = items.len() >= 2 && is_control_block(last);

    if !is_script_path {
        // Not a recognizable script-path spend: no exemptions. Every item is a
        // script-argument witness item and must respect the 256-byte cap (C4).
        for item in items {
            if item.len() > MAX_PUSH {
                out.push(Violation {
                    rule: "C4",
                    detail: format!(
                        "input {input_idx}: non-exempt witness item {} bytes > {MAX_PUSH}",
                        item.len()
                    ),
                });
            }
        }
        return;
    }

    // Taproot script-path spend: last = control block, second-to-last = tapleaf.
    let cb = last;
    let script_bytes = items[items.len() - 2];

    // C6: control block size. (Length shape 33 + 32*m and leaf version were
    // already checked by `is_control_block`; re-affirm the upper bound here.)
    if cb.len() > MAX_CONTROL_BLOCK {
        out.push(Violation {
            rule: "C6",
            detail: format!(
                "input {input_idx}: control block {} bytes > {MAX_CONTROL_BLOCK}",
                cb.len()
            ),
        });
    }
    // C9b: leaf version must be the defined TapScript version 0xc0 (parity bit
    // may set the low bit). Guaranteed by `is_control_block`, kept for clarity.
    if let Some(&first) = cb.first() {
        if first & 0xfe != 0xc0 {
            out.push(Violation {
                rule: "C9",
                detail: format!(
                    "input {input_idx}: undefined leaf version 0x{first:02x} (expected 0xc0/0xc1)"
                ),
            });
        }
    }

    // C4: every witness item other than the exempt tapleaf script and the
    // control block must be <= 256 bytes. Any leading items (e.g. a 64/65-byte
    // Schnorr signature) remain subject to the cap and pass it.
    for (i, item) in items.iter().enumerate() {
        let is_cb = i == items.len() - 1;
        let is_tapscript = i == items.len() - 2;
        if is_cb || is_tapscript {
            continue;
        }
        if item.len() > MAX_PUSH {
            out.push(Violation {
                rule: "C4",
                detail: format!(
                    "input {input_idx}: non-exempt witness item {} bytes > {MAX_PUSH}",
                    item.len()
                ),
            });
        }
    }

    // C7/C8: scan the tapleaf script's opcode stream (its internal pushes are
    // still checked <= 256 even though the item itself is exempt).
    let script = ScriptBuf::from(script_bytes.to_vec());
    check_tapscript(&script, out);
}

/// Re-check every output's scriptPubKey (C1 size cap, C2 OP_RETURN exception).
fn check_outputs(tx: &Transaction, out: &mut Vec<Violation>) {
    for (i, txout) in tx.output.iter().enumerate() {
        let spk = &txout.script_pubkey;
        let len = spk.len();
        if spk.is_op_return() {
            if len > MAX_OP_RETURN_SPK {
                out.push(Violation {
                    rule: "C2",
                    detail: format!(
                        "output {i}: OP_RETURN scriptPubKey {len} bytes > {MAX_OP_RETURN_SPK}"
                    ),
                });
            }
        } else if len > MAX_SPK {
            out.push(Violation {
                rule: "C1",
                detail: format!("output {i}: scriptPubKey {len} bytes > {MAX_SPK}"),
            });
        }
    }
}

/// Collect all BIP-110 violations found in `tx`. An empty vector means the
/// transaction passes every check this module can perform.
pub fn check(tx: &Transaction) -> Vec<Violation> {
    let mut out = Vec::new();
    check_outputs(tx, &mut out);
    for (idx, input) in tx.input.iter().enumerate() {
        let items: Vec<&[u8]> = input.witness.iter().collect();
        check_witness(idx, &items, &mut out);
    }
    out
}

/// Validate `tx`, returning `Err` with all violations if any rule is broken.
pub fn validate(tx: &Transaction) -> Result<(), Vec<Violation>> {
    let v = check(tx);
    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot_spend::{build_tx, dummy_prevout};
    use bitcoin::absolute::LockTime;
    use bitcoin::opcodes::all::OP_PUSHNUM_1;
    use bitcoin::script::{Builder, PushBytesBuf};
    use bitcoin::transaction::Version;

    #[test]
    fn generated_tx_passes_validation() {
        let data: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        let tx = build_tx(&data, dummy_prevout(0)).unwrap();
        assert_eq!(validate(&tx), Ok(()), "generated tx must be compliant");
    }

    #[test]
    fn oversized_push_is_rejected() {
        // Deliberately non-compliant: a single 300-byte push (> 256).
        let big = PushBytesBuf::try_from(vec![0xEEu8; 300]).unwrap();
        let bad_script = Builder::new()
            .push_slice(&big)
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .push_opcode(OP_PUSHNUM_1)
            .into_script();

        // Wrap it in an otherwise well-formed script-path witness so only the
        // 300-byte push trips validation.
        let bundle = crate::taproot_spend::build_spend(b"x").unwrap();
        let mut witness = bitcoin::Witness::new();
        witness.push(bad_script.as_bytes());
        witness.push(bundle.control_block.serialize());

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: dummy_prevout(0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: bundle.spk,
            }],
        };

        let res = validate(&tx);
        assert!(res.is_err(), "300-byte push must be rejected");
        assert!(
            res.unwrap_err().iter().any(|v| v.rule == "C3"),
            "expected a C3 (per-push cap) violation"
        );
    }

    #[test]
    fn oversized_output_spk_is_rejected() {
        // A 40-byte non-OP_RETURN scriptPubKey violates C1.
        let big_spk = ScriptBuf::from(vec![0x00u8; 40]);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: big_spk,
            }],
        };
        let err = validate(&tx).unwrap_err();
        assert!(err.iter().any(|v| v.rule == "C1"));
    }

    #[test]
    fn checksig_signed_spend_has_3_item_witness_and_passes() {
        use crate::taproot_spend::{build_signed_spend, dummy_prevout};
        use crate::tapscript::Auth;
        use bitcoin::{Amount, Network};

        let data: Vec<u8> = (0..2_000u32).map(|i| i as u8).collect();
        // A throwaway regtest destination address.
        let to = crate::taproot_spend::commit_address(b"dest", Auth::None, Network::Regtest)
            .unwrap()
            .script_pubkey();
        let tx = build_signed_spend(
            &data,
            Auth::Checksig,
            dummy_prevout(0),
            Amount::from_sat(100_000),
            &to,
            Amount::from_sat(1_000),
            Network::Regtest,
        )
        .unwrap();

        let items: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert_eq!(items.len(), 3, "checksig witness must be [sig, script, cb]");
        assert_eq!(items[0].len(), 64, "first item is a 64-byte Schnorr sig");
        assert_eq!(items[2].len(), 33, "single-leaf control block is 33 bytes");
        assert_eq!(items[2][0] & 0xfe, 0xc0);
        // Output value == prevout_value - fee.
        assert_eq!(tx.output[0].value, Amount::from_sat(99_000));
        assert_eq!(validate(&tx), Ok(()), "checksig spend must be compliant");
    }

    #[test]
    fn none_signed_spend_has_2_item_witness_and_passes() {
        use crate::taproot_spend::{build_signed_spend, dummy_prevout};
        use crate::tapscript::Auth;
        use bitcoin::{Amount, Network};

        let data: Vec<u8> = (0..1_500u32).map(|i| i as u8).collect();
        let to = crate::taproot_spend::commit_address(b"dest2", Auth::None, Network::Regtest)
            .unwrap()
            .script_pubkey();
        let tx = build_signed_spend(
            &data,
            Auth::None,
            dummy_prevout(1),
            Amount::from_sat(50_000),
            &to,
            Amount::from_sat(500),
            Network::Regtest,
        )
        .unwrap();

        let items: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert_eq!(items.len(), 2, "none witness must be [script, cb]");
        assert_eq!(items[1].len(), 33);
        assert_eq!(tx.output[0].value, Amount::from_sat(49_500));
        assert_eq!(validate(&tx), Ok(()), "none spend must be compliant");
    }

    #[test]
    fn annex_is_rejected() {
        let bundle = crate::taproot_spend::build_spend(b"data").unwrap();
        let mut witness = bitcoin::Witness::new();
        witness.push(bundle.script.as_bytes());
        witness.push(bundle.control_block.serialize());
        witness.push([ANNEX_TAG, 0x01, 0x02].as_slice()); // annex begins with 0x50

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: dummy_prevout(0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0),
                script_pubkey: bundle.spk,
            }],
        };
        let err = validate(&tx).unwrap_err();
        assert!(err.iter().any(|v| v.rule == "C5"), "annex must be rejected");
    }
}
