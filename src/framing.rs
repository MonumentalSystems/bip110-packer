//! Compression pre-pass and self-describing framing for channel payloads.
//!
//! Every channel encodes an opaque byte string. Before a payload is handed to a
//! channel it is **framed**: a single header byte is prepended describing how the
//! bytes that follow are encoded, so the decoder can recover the original blob
//! without any out-of-band metadata.
//!
//! Header byte:
//! * `0x00` — the following bytes are the raw payload.
//! * `0x01` — the following bytes are DEFLATE-compressed (via `miniz_oxide`);
//!   inflate them to recover the payload.
//!
//! The framing is transparent to a channel: a channel round-trips the *framed*
//! bytes, and the caller (CLI) calls [`unframe`] on the recovered bytes to get
//! the original payload back.

use anyhow::{anyhow, Result};

/// Header byte marking a raw (uncompressed) payload.
pub const HEADER_RAW: u8 = 0x00;
/// Header byte marking a DEFLATE-compressed payload.
pub const HEADER_DEFLATE: u8 = 0x01;

/// DEFLATE compression level used by [`frame`] (0..=10; 6 is a good size/speed
/// tradeoff for `miniz_oxide`).
const COMPRESSION_LEVEL: u8 = 6;

/// Frame `data` with a 1-byte header.
///
/// * `compress == false` → header `0x00` followed by `data` verbatim.
/// * `compress == true` → attempt DEFLATE. If the compressed form is strictly
///   smaller than the raw payload, emit header `0x01` + compressed bytes;
///   otherwise fall back to the raw framing (`0x00` + `data`) so framing never
///   inflates an incompressible payload.
pub fn frame(data: &[u8], compress: bool) -> Vec<u8> {
    if compress {
        let compressed = miniz_oxide::deflate::compress_to_vec(data, COMPRESSION_LEVEL);
        if compressed.len() < data.len() {
            let mut out = Vec::with_capacity(compressed.len() + 1);
            out.push(HEADER_DEFLATE);
            out.extend_from_slice(&compressed);
            return out;
        }
    }
    let mut out = Vec::with_capacity(data.len() + 1);
    out.push(HEADER_RAW);
    out.extend_from_slice(data);
    out
}

/// Reverse [`frame`]: read the header byte and return the original payload.
///
/// Errors if the buffer is empty (no header) or the header byte is unknown, or if
/// DEFLATE inflation fails.
pub fn unframe(framed: &[u8]) -> Result<Vec<u8>> {
    let (&header, rest) = framed
        .split_first()
        .ok_or_else(|| anyhow!("empty framed buffer: missing header byte"))?;
    match header {
        HEADER_RAW => Ok(rest.to_vec()),
        HEADER_DEFLATE => miniz_oxide::inflate::decompress_to_vec(rest)
            .map_err(|e| anyhow!("DEFLATE inflate failed: {e:?}")),
        other => Err(anyhow!("unknown framing header byte 0x{other:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8], compress: bool) {
        let framed = frame(data, compress);
        let back = unframe(&framed).expect("unframe");
        assert_eq!(back, data, "round-trip failed (compress={compress})");
    }

    #[test]
    fn roundtrip_raw_and_compressed_empty_small_and_10k() {
        let empty: &[u8] = &[];
        let small: &[u8] = b"the quick brown fox";
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        for compress in [false, true] {
            roundtrip(empty, compress);
            roundtrip(small, compress);
            roundtrip(&big, compress);
        }
    }

    #[test]
    fn compressible_input_shrinks_and_uses_deflate_header() {
        let zeros = vec![0u8; 10_000];
        let framed = frame(&zeros, true);
        assert_eq!(
            framed[0], HEADER_DEFLATE,
            "compressible payload must deflate"
        );
        assert!(framed.len() < zeros.len(), "compression must shrink zeros");
        assert_eq!(unframe(&framed).unwrap(), zeros);
    }

    #[test]
    fn incompressible_input_falls_back_to_raw() {
        // A tiny payload: DEFLATE's framing overhead always exceeds the savings,
        // so `frame` must fall back to the raw header rather than inflate it.
        let data = b"abc";
        let framed = frame(data, true);
        assert_eq!(framed[0], HEADER_RAW, "tiny payload must fall back to raw");
        assert_eq!(unframe(&framed).unwrap(), data);
    }

    #[test]
    fn raw_framing_prepends_zero_header() {
        let framed = frame(b"abc", false);
        assert_eq!(framed, vec![HEADER_RAW, b'a', b'b', b'c']);
    }

    #[test]
    fn unframe_rejects_empty_and_unknown_header() {
        assert!(unframe(&[]).is_err());
        assert!(unframe(&[0xFF, 0x00]).is_err());
    }
}
