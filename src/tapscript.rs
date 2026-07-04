//! Tapscript builder: chunk arbitrary bytes and emit `push … OP_2DROP … OP_1`.
//!
//! Uses the most data-dense legal chunk size: **255 bytes**, pushed with
//! `OP_PUSHDATA1` and discarded in pairs by `OP_2DROP`. See the crate-level docs
//! for the density analysis.

use bitcoin::opcodes::all::{OP_2DROP, OP_CHECKSIG, OP_DROP, OP_PUSHNUM_1};
use bitcoin::script::{Builder, Instruction, PushBytesBuf, ScriptBuf};

/// The ordinals-style protocol identifier pushed first in a BIP-110 envelope
/// (matches `ordinals/ord` PR #4545: the ASCII bytes `b"ord"`).
pub const PROTOCOL_ID: [u8; 3] = *b"ord";

/// Spend-authorization mode for a data-carrying tapscript.
///
/// * [`Auth::None`] — anyone-can-spend. The tapscript is `<ord-envelope> OP_1`,
///   so the final stack is exactly `[1]`. Witness = `[script, control_block]`.
/// * [`Auth::Checksig`] — a `<32-byte x-only pubkey> OP_CHECKSIG` prefix runs
///   *before* the (depth-neutral) ord envelope, leaving a single bool on the
///   stack. No trailing `OP_1`. Witness = `[schnorr_sig, script, control_block]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Auth {
    /// Anyone-can-spend: envelope terminated with `OP_1`.
    #[default]
    None,
    /// Requires a Schnorr signature from the reveal key (via `OP_CHECKSIG`).
    Checksig,
}

/// Deliberate BIP-110 violation selector for the **violation generator**.
///
/// These constructions are intentionally NON-COMPLIANT and exist only for
/// enforcement testing and the node-side "gap demo". Every variant except an
/// output-level violation still produces a *spendable* anyone-can-spend tapleaf
/// (final stack exactly one truthy element) so a non-enforcing node will mine it
/// while [`crate::bip110::validate`] rejects it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Violate {
    /// No violation: identical to `build_tapscript_auth(data, Auth::None)`.
    #[default]
    None,
    /// C3: inject a single 300-byte push (balanced by `OP_DROP`, stack-neutral).
    PushTooBig,
    /// C8: include an `OP_IF … OP_ENDIF` that actually executes.
    OpIf,
    /// C7: append an `OP_SUCCESSx` opcode (`OP_VER` / 0x62 == OP_SUCCESS98).
    OpSuccess,
}

/// Most data-dense per-push chunk size under BIP-110.
///
/// BIP-110 caps every `OP_PUSHDATA*` payload *inside* a script at 256 bytes.
/// 255 bytes uses `OP_PUSHDATA1` (2 overhead bytes); 256 would force
/// `OP_PUSHDATA2` (3 overhead bytes), which is strictly less efficient.
pub const CHUNK_SIZE: usize = 255;

/// Build a data-carrying tapscript from an arbitrary byte blob.
///
/// The produced script is:
/// `{ push <=255B> push <=255B> OP_2DROP }* [ push <=255B> OP_DROP ]? OP_1`
///
/// * Every push payload is `<= CHUNK_SIZE (255) <= 256`, satisfying the
///   BIP-110 per-push cap.
/// * Peak main-stack depth is 2 (well under the 1000-element combined limit).
/// * The trailing `OP_1` leaves exactly one truthy element, satisfying the
///   BIP342 consensus "exactly one truthy stack element" termination rule.
/// * Contains no `OP_IF`/`OP_NOTIF` and no `OP_SUCCESS*` opcodes.
pub fn build_tapscript(data: &[u8]) -> ScriptBuf {
    let chunks: Vec<&[u8]> = if data.is_empty() {
        Vec::new()
    } else {
        data.chunks(CHUNK_SIZE).collect()
    };

    let mut b = Builder::new();
    let mut i = 0usize;

    // Drop chunks two-at-a-time with a single OP_2DROP (0.5 byte/chunk).
    while i + 1 < chunks.len() {
        let buf0 = to_push(chunks[i]);
        let buf1 = to_push(chunks[i + 1]);
        b = b.push_slice(&buf0).push_slice(&buf1).push_opcode(OP_2DROP);
        i += 2;
    }

    // Odd trailing chunk: push then single OP_DROP.
    if i < chunks.len() {
        let buf = to_push(chunks[i]);
        b = b.push_slice(&buf).push_opcode(OP_DROP);
    }

    // Terminate with OP_1 == OP_PUSHNUM_1 (0x51): one truthy element on the
    // stack so the script satisfies BIP342's exactly-one-truthy consensus rule.
    b = b.push_opcode(OP_PUSHNUM_1);
    b.into_script()
}

/// Derive the x-only reveal public key (32 bytes) used by [`Auth::Checksig`].
///
/// The reveal keypair is derived deterministically (no RNG) from the fixed
/// [`crate::taproot_spend::REVEAL_KEY_SECRET`] bytes.
pub fn reveal_xonly_bytes() -> [u8; 32] {
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::secp256k1::SecretKey;
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&crate::taproot_spend::REVEAL_KEY_SECRET)
        .expect("reveal secret in range");
    let kp = Keypair::from_secret_key(&secp, &sk);
    kp.x_only_public_key().0.serialize()
}

/// Append an ord-compatible, **depth-neutral** BIP-110 envelope for `data` onto
/// an existing [`Builder`].
///
/// Shape (canonical `ordinals/ord` PR #4545 form): a `PROTOCOL_ID` push followed
/// by 255-byte data-chunk pushes, all balanced back to stack-depth-0 by
/// `OP_2DROP` (drops 2) plus a final `OP_DROP` when the total number of pushes
/// (protocol push included) is odd.
///
/// The protocol push acts as a "guard" element that stays on the stack until the
/// very end, so the running stack depth is kept in `[1, 3]` and never hits 0
/// prematurely (which would end the envelope early for a depth-tracking parser).
fn append_envelope(mut b: Builder, data: &[u8]) -> Builder {
    let chunks: Vec<&[u8]> = if data.is_empty() {
        Vec::new()
    } else {
        data.chunks(CHUNK_SIZE).collect()
    };

    // Push the protocol id first (this is the guard element, depth -> 1).
    let pid = to_push(&PROTOCOL_ID);
    b = b.push_slice(&pid);

    // Drop data chunks two-at-a-time (guard untouched); depth oscillates 1..3.
    let mut i = 0usize;
    while i + 1 < chunks.len() {
        let buf0 = to_push(chunks[i]);
        let buf1 = to_push(chunks[i + 1]);
        b = b.push_slice(&buf0).push_slice(&buf1).push_opcode(OP_2DROP);
        i += 2;
    }

    if i < chunks.len() {
        // Odd number of data chunks: push the leftover (depth -> 2 with guard),
        // then OP_2DROP removes both the leftover and the guard (depth -> 0).
        let buf = to_push(chunks[i]);
        b = b.push_slice(&buf).push_opcode(OP_2DROP);
    } else {
        // Even number of data chunks: only the guard remains; OP_DROP it
        // (depth -> 0). Total pushes = 1 + even = odd, so a single OP_DROP.
        b = b.push_opcode(OP_DROP);
    }

    b
}

/// Build a standalone ord-compatible BIP-110 envelope fragment for `data`.
///
/// The result is depth-neutral (pushes N+1 items, drops exactly N+1). Round-trip
/// the original bytes back out with [`extract_ord_payload`].
pub fn build_envelope(data: &[u8]) -> ScriptBuf {
    append_envelope(Builder::new(), data).into_script()
}

/// Build a data-carrying tapscript with an explicit [`Auth`] mode.
///
/// * [`Auth::None`]: `<ord-envelope> OP_1` — final stack `[1]`.
/// * [`Auth::Checksig`]: `<32B reveal pubkey> OP_CHECKSIG <ord-envelope>` — the
///   `OP_CHECKSIG` runs *outside* (before) the envelope so the ord parser, which
///   rejects any non-push/DROP/2DROP opcode inside the envelope, stays happy. It
///   leaves a bool that the depth-neutral envelope preserves, so the final stack
///   is exactly one truthy element. No trailing `OP_1`.
pub fn build_tapscript_auth(data: &[u8], auth: Auth) -> ScriptBuf {
    match auth {
        Auth::None => {
            let b = append_envelope(Builder::new(), data);
            b.push_opcode(OP_PUSHNUM_1).into_script()
        }
        Auth::Checksig => {
            let pk = reveal_xonly_bytes();
            let pk_push = to_push(&pk);
            let mut b = Builder::new().push_slice(&pk_push).push_opcode(OP_CHECKSIG);
            b = append_envelope(b, data);
            b.into_script()
        }
    }
}

/// Build a **deliberately BIP-110-NON-COMPLIANT** data-carrying tapleaf with
/// exactly one injected violation, for enforcement testing only.
///
/// Every variant (except an output-level violation, which is not a leaf concern)
/// still produces an anyone-can-spend script that executes to exactly one truthy
/// stack element, so a non-enforcing node will accept and mine it while
/// [`crate::bip110::validate`] flags the rule below:
///
/// * [`Violate::None`] — identical to `build_tapscript_auth(data, Auth::None)`.
/// * [`Violate::PushTooBig`] (C3) — `<300B> OP_DROP <ord-envelope> OP_1`. The
///   300-byte push (`> 256`, `<= 520`) executes fine and is immediately dropped,
///   leaving the normal envelope + `OP_1` (final stack `[1]`).
/// * [`Violate::OpIf`] (C8) — `<ord-envelope> OP_1 OP_IF OP_1 OP_ENDIF`. The
///   `OP_IF` executes on a truthy value and re-pushes `OP_1` (final stack `[1]`).
/// * [`Violate::OpSuccess`] (C7) — `<ord-envelope> OP_1 OP_VER`. `OP_VER` is
///   `OP_SUCCESS98` under BIP342, making the whole tapscript unconditionally
///   valid (the node accepts it regardless of the rest of the stack).
///
/// `extract_ord_payload` still round-trips the data for None/PushTooBig/OpIf.
pub fn build_tapscript_violation(data: &[u8], violate: Violate) -> ScriptBuf {
    use bitcoin::opcodes::all::{OP_ENDIF, OP_IF, OP_VER};
    match violate {
        Violate::None => build_tapscript_auth(data, Auth::None),
        Violate::PushTooBig => {
            // 300 > 256 (C3) but <= 520, so it executes; OP_DROP keeps the stack
            // neutral before the normal envelope + OP_1 terminator.
            let big = to_push(&vec![0xEEu8; 300]);
            let mut b = Builder::new().push_slice(&big).push_opcode(OP_DROP);
            b = append_envelope(b, data);
            b.push_opcode(OP_PUSHNUM_1).into_script()
        }
        Violate::OpIf => {
            // INVARIANT: the OP_IF argument must stay minimally-encoded (here the
            // `0x01` produced by OP_PUSHNUM_1). BIP342's MINIMALIF is a *consensus*
            // rule in tapscript, so a non-minimal truthy push before OP_IF would be
            // rejected by *every* node as `bad-minimalif` — masking the BIP-110 C8
            // ban and silently breaking the enforcement/gap demo. A BIP-110-enforcing
            // node rejects this leaf for executing OP_IF at all; a non-enforcing node
            // accepts it (0x01 is minimal). Do not change the pre-OP_IF terminator.
            let b = append_envelope(Builder::new(), data);
            b.push_opcode(OP_PUSHNUM_1)
                .push_opcode(OP_IF)
                .push_opcode(OP_PUSHNUM_1)
                .push_opcode(OP_ENDIF)
                .into_script()
        }
        Violate::OpSuccess => {
            let b = append_envelope(Builder::new(), data);
            b.push_opcode(OP_PUSHNUM_1)
                .push_opcode(OP_VER)
                .into_script()
        }
    }
}

/// Extract the original bytes from an ord-compatible envelope tapscript.
///
/// Finds the first `PROTOCOL_ID` (`b"ord"`) push and concatenates every
/// subsequent push payload (the data chunks). Any leading pushes/opcodes before
/// the protocol id (e.g. the `<pubkey> OP_CHECKSIG` prefix of [`Auth::Checksig`])
/// are ignored, as are all `OP_2DROP`/`OP_DROP`/`OP_1` opcodes. Returns an empty
/// vector if no protocol id is found.
pub fn extract_ord_payload(script: &ScriptBuf) -> Vec<u8> {
    let mut out = Vec::new();
    let mut seen_pid = false;
    for ins in script.instructions() {
        match ins {
            Ok(Instruction::PushBytes(pb)) => {
                if seen_pid {
                    out.extend_from_slice(pb.as_bytes());
                } else if pb.as_bytes() == PROTOCOL_ID {
                    seen_pid = true;
                }
            }
            Ok(Instruction::Op(_)) => {}
            Err(_) => break,
        }
    }
    out
}

/// Convert a `<= u32::MAX`-length slice into a `PushBytesBuf`. Panics only if the
/// slice is longer than `u32::MAX` (impossible for our 255-byte chunks).
fn to_push(chunk: &[u8]) -> PushBytesBuf {
    PushBytesBuf::try_from(chunk.to_vec()).expect("chunk length fits in u32")
}

/// Extract the pushed data payloads back out of a tapscript, in order.
///
/// This is the inverse of [`build_tapscript`] for round-tripping: it collects
/// every push instruction's bytes and ignores the `OP_2DROP`/`OP_DROP`/`OP_1`
/// opcodes. Returns an error if the script is malformed.
pub fn extract_data(script: &ScriptBuf) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for ins in script.instructions() {
        match ins {
            Ok(Instruction::PushBytes(pb)) => out.extend_from_slice(pb.as_bytes()),
            Ok(Instruction::Op(_)) => {}
            Err(e) => return Err(format!("malformed script: {e}")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_various_lengths() {
        for len in [0usize, 1, 254, 255, 256, 509, 510, 511, 5000, 100_000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let script = build_tapscript(&data);
            let back = extract_data(&script).expect("valid script");
            assert_eq!(back, data, "roundtrip failed for len {len}");
        }
    }

    #[test]
    fn every_push_at_most_256_bytes() {
        let data: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        let script = build_tapscript(&data);
        for ins in script.instructions() {
            if let Ok(Instruction::PushBytes(pb)) = ins {
                assert!(pb.as_bytes().len() <= 256, "push exceeded 256 bytes");
            }
        }
    }

    #[test]
    fn no_op_if_or_notif_opcode_present() {
        // 0x63 = OP_IF, 0x64 = OP_NOTIF. Ensure they never appear at an opcode
        // position (payload bytes are parsed as data, not opcodes).
        let data: Vec<u8> = vec![0x63u8; 4000]; // payload full of 0x63 must be fine
        let script = build_tapscript(&data);
        for ins in script.instructions() {
            if let Ok(Instruction::Op(op)) = ins {
                let b = op.to_u8();
                assert_ne!(b, 0x63, "OP_IF opcode present");
                assert_ne!(b, 0x64, "OP_NOTIF opcode present");
            }
        }
    }

    #[test]
    fn ord_envelope_roundtrip_various_lengths() {
        for len in [0usize, 1, 255, 256, 510, 5000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
            let script = build_envelope(&data);
            let back = extract_ord_payload(&script);
            assert_eq!(back, data, "ord envelope roundtrip failed for len {len}");

            // The envelope's pushes must all be <= 255 bytes (BIP-110 per-push).
            for ins in script.instructions() {
                if let Ok(Instruction::PushBytes(pb)) = ins {
                    assert!(pb.as_bytes().len() <= 255, "envelope push > 255 bytes");
                }
            }
        }
    }

    #[test]
    fn auth_none_terminates_with_op_1_and_roundtrips() {
        let data = b"hello ord envelope".to_vec();
        let script = build_tapscript_auth(&data, Auth::None);
        assert_eq!(extract_ord_payload(&script), data);
        let last = script
            .instructions()
            .last()
            .expect("non-empty")
            .expect("valid");
        assert!(
            matches!(last, Instruction::Op(op) if op == OP_PUSHNUM_1),
            "Auth::None must end with OP_1"
        );
    }

    #[test]
    fn auth_checksig_has_pubkey_checksig_before_ord_and_no_op_1() {
        let data = b"authenticated data".to_vec();
        let script = build_tapscript_auth(&data, Auth::Checksig);

        // Walk instructions: expect <32B push> then OP_CHECKSIG, both BEFORE the
        // first `ord` protocol push.
        let ins: Vec<Instruction> = script
            .instructions()
            .map(|r| r.expect("valid instruction"))
            .collect();

        // First instruction: a 32-byte push (the x-only reveal pubkey).
        match &ins[0] {
            Instruction::PushBytes(pb) => assert_eq!(pb.as_bytes().len(), 32),
            _ => panic!("first instruction must be the 32-byte pubkey push"),
        }
        // Second instruction: OP_CHECKSIG.
        assert!(
            matches!(&ins[1], Instruction::Op(op) if *op == OP_CHECKSIG),
            "second instruction must be OP_CHECKSIG"
        );

        // The `ord` protocol push appears after OP_CHECKSIG.
        let pid_pos = ins
            .iter()
            .position(|i| matches!(i, Instruction::PushBytes(pb) if pb.as_bytes() == PROTOCOL_ID))
            .expect("protocol id present");
        assert!(pid_pos >= 2, "OP_CHECKSIG/pubkey must precede the ord push");

        // No OP_1 terminator anywhere.
        assert!(
            !ins.iter()
                .any(|i| matches!(i, Instruction::Op(op) if *op == OP_PUSHNUM_1)),
            "Auth::Checksig must NOT contain an OP_1 terminator"
        );

        // Round-trip still works (pubkey/checksig prefix ignored).
        assert_eq!(extract_ord_payload(&script), data);
    }

    #[test]
    fn violation_leaves_roundtrip_and_inject_expected_opcode() {
        let data = b"violation generator payload".to_vec();

        // None == Auth::None.
        assert_eq!(
            build_tapscript_violation(&data, Violate::None),
            build_tapscript_auth(&data, Auth::None)
        );

        // PushTooBig: a 300-byte push present; still round-trips.
        let s = build_tapscript_violation(&data, Violate::PushTooBig);
        assert_eq!(extract_ord_payload(&s), data);
        assert!(
            s.instructions()
                .any(|i| matches!(i, Ok(Instruction::PushBytes(pb)) if pb.as_bytes().len() == 300)),
            "PushTooBig must contain a 300-byte push"
        );

        // OpIf: OP_IF opcode present; still round-trips.
        let s = build_tapscript_violation(&data, Violate::OpIf);
        assert_eq!(extract_ord_payload(&s), data);
        assert!(
            s.instructions()
                .any(|i| matches!(i, Ok(Instruction::Op(op)) if op.to_u8() == 0x63)),
            "OpIf must contain OP_IF (0x63)"
        );

        // OpSuccess: OP_VER (0x62) present.
        let s = build_tapscript_violation(&data, Violate::OpSuccess);
        assert!(
            s.instructions()
                .any(|i| matches!(i, Ok(Instruction::Op(op)) if op.to_u8() == 0x62)),
            "OpSuccess must contain OP_VER/OP_SUCCESS98 (0x62)"
        );
    }

    #[test]
    fn ends_with_op_true() {
        let script = build_tapscript(b"hello world");
        let last = script
            .instructions()
            .last()
            .expect("non-empty")
            .expect("valid");
        match last {
            Instruction::Op(op) => assert_eq!(op, OP_PUSHNUM_1),
            _ => panic!("script did not end with OP_1"),
        }
    }
}
