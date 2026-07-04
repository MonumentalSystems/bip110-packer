//! Block packer: fill up to ~4,000,000 WU with data-carrying transactions,
//! tracking cumulative weight and stopping before overflow.

use anyhow::Result;
use bitcoin::Transaction;

use crate::taproot_spend::{build_tx, dummy_prevout};
use crate::tapscript::CHUNK_SIZE;

/// Consensus block weight limit.
pub const BLOCK_WEIGHT_LIMIT: u64 = 4_000_000;

/// Weight reserved for the coinbase transaction (with witness commitment) and
/// slack. Generous so the packed data txs never push the block over the limit.
pub const COINBASE_RESERVE: u64 = 2_000;

/// Script bytes carried per `push,push,OP_2DROP` pair: `2*(2+255)+1 = 515`.
const PAIR_SCRIPT_BYTES: u64 = 515;
/// Data bytes carried per pair: `2*255 = 510`.
const PAIR_DATA_BYTES: usize = 2 * CHUNK_SIZE;

/// Result of packing a data blob into a block's worth of transactions.
pub struct PackResult {
    /// The generated, block-ready transactions.
    pub txs: Vec<Transaction>,
    /// Total arbitrary data bytes actually packed.
    pub bytes_packed: usize,
    /// Cumulative weight (WU) consumed by the data transactions.
    pub weight_used: u64,
    /// Weight budget available to data txs (block limit minus coinbase reserve).
    pub budget: u64,
    /// Data-per-weight efficiency: `100 * bytes_packed / weight_used` (%).
    /// The theoretical ceiling is ~100% (witness bytes cost 1 WU/byte).
    pub efficiency: f64,
}

/// Estimate the maximum arbitrary-data byte count whose transaction fits within
/// `budget` weight units. Conservative (leaves a few bytes of margin for the
/// script-length varint growing to its 5-byte form), so the packer's trim loop
/// rarely fires.
fn max_data_for_budget(budget: u64) -> usize {
    // Fixed per-tx overhead = weight of a tx whose script is just OP_1.
    let base = build_tx(&[], dummy_prevout(0))
        .expect("empty tx builds")
        .weight()
        .to_wu();
    // 8 WU margin covers the compact-size script-length varint growing from
    // 1 byte (tiny script) to 5 bytes (~4 MB script).
    if budget <= base + 8 {
        return 0;
    }
    let avail = budget - base - 8;
    let pairs = avail / PAIR_SCRIPT_BYTES;
    (pairs as usize) * PAIR_DATA_BYTES
}

/// Pack `data` into as many transactions as fit within the block weight budget,
/// stopping before overflow. If `data` is larger than one block can hold, only
/// the prefix that fits is packed.
pub fn pack(data: &[u8]) -> Result<PackResult> {
    let budget = BLOCK_WEIGHT_LIMIT - COINBASE_RESERVE;
    let mut used: u64 = 0;
    let mut txs: Vec<Transaction> = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let remaining_budget = budget - used;
        let cap = max_data_for_budget(remaining_budget);
        if cap == 0 {
            break;
        }
        let mut take = cap.min(data.len() - offset);

        let prevout = dummy_prevout(txs.len() as u32);
        let mut tx = build_tx(&data[offset..offset + take], prevout)?;

        // Safety trim: if the estimate was slightly optimistic, shed one pair at
        // a time until the tx fits the remaining budget.
        while tx.weight().to_wu() > remaining_budget && take > 0 {
            take = take.saturating_sub(PAIR_DATA_BYTES);
            let end = offset + take.min(data.len() - offset);
            tx = build_tx(&data[offset..end], prevout)?;
        }

        let w = tx.weight().to_wu();
        if w > remaining_budget || take == 0 {
            break;
        }

        used += w;
        offset += take;
        txs.push(tx);
    }

    let bytes_packed = offset;
    let efficiency = if used > 0 {
        100.0 * bytes_packed as f64 / used as f64
    } else {
        0.0
    };

    Ok(PackResult {
        txs,
        bytes_packed,
        weight_used: used,
        budget,
        efficiency,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_blob_fits_in_one_tx_under_budget() {
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let res = pack(&data).unwrap();
        assert_eq!(res.bytes_packed, data.len());
        assert_eq!(res.txs.len(), 1);
        assert!(res.weight_used < BLOCK_WEIGHT_LIMIT);
    }

    #[test]
    fn cumulative_weight_stays_under_block_limit() {
        // A blob far larger than one block can hold; packer must stop cleanly.
        let data = vec![0x5Au8; 8_000_000];
        let res = pack(&data).unwrap();
        assert!(
            res.weight_used <= res.budget,
            "weight {} exceeded budget {}",
            res.weight_used,
            res.budget
        );
        assert!(res.weight_used < BLOCK_WEIGHT_LIMIT);
        // Sum of individual tx weights must equal the tracked total.
        let sum: u64 = res.txs.iter().map(|t| t.weight().to_wu()).sum();
        assert_eq!(sum, res.weight_used);
        // Should pack roughly ~3.9 MB into one block.
        assert!(
            res.bytes_packed > 3_800_000,
            "only packed {} bytes",
            res.bytes_packed
        );
    }

    #[test]
    fn efficiency_is_near_one_byte_per_weight_unit() {
        let data = vec![0x11u8; 2_000_000];
        let res = pack(&data).unwrap();
        assert!(
            res.efficiency > 98.0 && res.efficiency <= 100.0,
            "efficiency {} out of expected range",
            res.efficiency
        );
    }
}
