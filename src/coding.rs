//! Reed-Solomon 64-of-128 payload coding over GF(2⁸).
//!
//! Shared by `rs-partial` and `rs-subnets`. `shard_len = ceil(payload_len / 64)`;
//! reconstruction verifies SHA-256 of the original (unpadded) payload.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Number of original (systematic) data shards a payload is split into.
pub const PAYLOAD_DATA_SHARDS: usize = 64;
/// Number of Reed-Solomon parity shards generated alongside the data shards.
pub const PAYLOAD_PARITY_SHARDS: usize = 64;
/// Total shards (data + parity) propagated over the chunk / column topics.
pub const PAYLOAD_TOTAL_SHARDS: usize = PAYLOAD_DATA_SHARDS + PAYLOAD_PARITY_SHARDS;

/// Largest total shard count representable over GF(2⁸): `reed_solomon_erasure`
/// rejects `data + parity > 256`.
pub const MAX_TOTAL_SHARDS: usize = 256;

/// Reed-Solomon rate for one payload: `data` systematic shards extended to
/// `total`, reconstructable from any `data` of them.
///
/// `rs-partial`, `rs-subnets`, and `hybrid` always use [`RsParams::DEFAULT`];
/// only `gossipsub-rs` exposes this as configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RsParams {
    pub data: usize,
    pub total: usize,
}

impl RsParams {
    /// The 64-of-128 rate every non-configurable mode uses.
    pub const DEFAULT: Self = Self {
        data: PAYLOAD_DATA_SHARDS,
        total: PAYLOAD_TOTAL_SHARDS,
    };

    pub fn new(data: usize, total: usize) -> Result<Self, PayloadCodingError> {
        let params = Self { data, total };
        params.validate()?;
        Ok(params)
    }

    pub fn parity(&self) -> usize {
        self.total.saturating_sub(self.data)
    }

    /// Reject rates Reed-Solomon cannot represent: at least one data shard, at
    /// least one parity shard, and at most [`MAX_TOTAL_SHARDS`] in total.
    pub fn validate(&self) -> Result<(), PayloadCodingError> {
        if self.data == 0 || self.total <= self.data || self.total > MAX_TOTAL_SHARDS {
            return Err(PayloadCodingError::InvalidRsParams {
                data: self.data,
                total: self.total,
            });
        }
        Ok(())
    }
}

impl Default for RsParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Errors from encoding or decoding a payload's shards.
#[derive(Debug)]
pub enum PayloadCodingError {
    EmptyPayload,
    Rs(reed_solomon_erasure::Error),
    InvalidShardIndex { idx: usize },
    InconsistentShardLength { expected: usize, got: usize },
    HashMismatch,
    InvalidRsParams { data: usize, total: usize },
}

impl fmt::Display for PayloadCodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => write!(f, "cannot encode an empty payload"),
            Self::Rs(e) => write!(f, "reed-solomon-erasure: {e}"),
            Self::InvalidShardIndex { idx } => {
                write!(f, "shard index {idx} out of range")
            }
            Self::InvalidRsParams { data, total } => {
                write!(
                    f,
                    "invalid reed-solomon rate {data}-of-{total}: need \
                     1 <= data < total <= {MAX_TOTAL_SHARDS}"
                )
            }
            Self::InconsistentShardLength { expected, got } => {
                write!(f, "shard length {got} differs from expected {expected}")
            }
            Self::HashMismatch => {
                write!(
                    f,
                    "reconstructed payload hash does not match the committed hash"
                )
            }
        }
    }
}

impl std::error::Error for PayloadCodingError {}

impl From<reed_solomon_erasure::Error> for PayloadCodingError {
    fn from(e: reed_solomon_erasure::Error) -> Self {
        Self::Rs(e)
    }
}

/// SHA-256 of `data` as a fixed 32-byte array.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// `(shard_len, payload_hash, shards)` — see [`encode_payload_shards`].
pub type EncodedPayloadShards = (usize, [u8; 32], Vec<Vec<u8>>);

/// Split `payload` into [`PAYLOAD_DATA_SHARDS`] zero-padded data shards and
/// Reed-Solomon-extend them to [`PAYLOAD_TOTAL_SHARDS`] total shards.
pub fn encode_payload_shards(payload: &[u8]) -> Result<EncodedPayloadShards, PayloadCodingError> {
    encode_payload_shards_with(payload, RsParams::DEFAULT)
}

/// [`encode_payload_shards`] at an explicit Reed-Solomon rate.
pub fn encode_payload_shards_with(
    payload: &[u8],
    params: RsParams,
) -> Result<EncodedPayloadShards, PayloadCodingError> {
    params.validate()?;
    if payload.is_empty() {
        return Err(PayloadCodingError::EmptyPayload);
    }
    let shard_len = payload.len().div_ceil(params.data);
    let rs = reed_solomon_erasure::galois_8::ReedSolomon::new(params.data, params.parity())?;
    let mut shards: Vec<Vec<u8>> = (0..params.total).map(|_| vec![0u8; shard_len]).collect();
    for (chunk, shard) in payload.chunks(shard_len).zip(shards.iter_mut()) {
        shard[..chunk.len()].copy_from_slice(chunk);
    }
    rs.encode(&mut shards)?;
    Ok((shard_len, sha256(payload), shards))
}

/// Reconstruct the payload from any `>= PAYLOAD_DATA_SHARDS` distinct shards.
/// Returns the original payload bytes and the full set of 128 shards.
pub fn decode_payload(
    payload_len: usize,
    shard_len: usize,
    payload_hash: &[u8; 32],
    shards: &[(usize, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<Vec<u8>>), PayloadCodingError> {
    decode_payload_with(payload_len, shard_len, payload_hash, shards, RsParams::DEFAULT)
}

/// [`decode_payload`] at an explicit Reed-Solomon rate.
pub fn decode_payload_with(
    payload_len: usize,
    shard_len: usize,
    payload_hash: &[u8; 32],
    shards: &[(usize, Vec<u8>)],
    params: RsParams,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), PayloadCodingError> {
    params.validate()?;
    let rs = reed_solomon_erasure::galois_8::ReedSolomon::new(params.data, params.parity())?;
    let mut buckets: Vec<Option<Vec<u8>>> = vec![None; params.total];
    for (idx, data) in shards {
        if *idx >= params.total {
            return Err(PayloadCodingError::InvalidShardIndex { idx: *idx });
        }
        if data.len() != shard_len {
            return Err(PayloadCodingError::InconsistentShardLength {
                expected: shard_len,
                got: data.len(),
            });
        }
        buckets[*idx] = Some(data.clone());
    }
    rs.reconstruct(&mut buckets)?;

    let mut full_shards = Vec::with_capacity(params.total);
    for slot in buckets {
        full_shards.push(slot.ok_or(PayloadCodingError::Rs(
            reed_solomon_erasure::Error::TooFewShardsPresent,
        ))?);
    }

    let mut out = Vec::with_capacity(params.data * shard_len);
    for shard in full_shards.iter().take(params.data) {
        out.extend_from_slice(shard);
    }
    if payload_len > out.len() {
        return Err(PayloadCodingError::InconsistentShardLength {
            expected: payload_len,
            got: out.len(),
        });
    }
    out.truncate(payload_len);

    if sha256(&out) != *payload_hash {
        return Err(PayloadCodingError::HashMismatch);
    }
    Ok((out, full_shards))
}

/// Full gossipsub message for one column subnet (mode `rs-subnets`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnShardMessage {
    pub index: u16,
    pub payload_len: u64,
    pub shard_len: u64,
    pub payload_hash: [u8; 32],
    pub data: Vec<u8>,
}

impl ColumnShardMessage {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize column shard")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    #[test]
    fn encode_decode_roundtrip_256_kib() {
        let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let (shard_len, hash, shards) = encode_payload_shards(&payload).unwrap();
        assert_eq!(shards.len(), PAYLOAD_TOTAL_SHARDS);
        let indexed: Vec<(usize, Vec<u8>)> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.clone()))
            .collect();
        let (recovered, _) = decode_payload(payload.len(), shard_len, &hash, &indexed).unwrap();
        assert_eq!(recovered, payload);
        assert_eq!(sha256(&recovered), hash);
    }

    #[test]
    fn drop_64_random_shards_still_decodes() {
        let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 256) as u8).collect();
        let (shard_len, hash, shards) = encode_payload_shards(&payload).unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let mut idx: Vec<usize> = (0..PAYLOAD_TOTAL_SHARDS).collect();
        for i in (1..idx.len()).rev() {
            let j = rng.random_range(0..=i);
            idx.swap(i, j);
        }
        let kept: Vec<(usize, Vec<u8>)> = idx
            .into_iter()
            .take(PAYLOAD_DATA_SHARDS)
            .map(|i| (i, shards[i].clone()))
            .collect();
        let (recovered, _) = decode_payload(payload.len(), shard_len, &hash, &kept).unwrap();
        assert_eq!(recovered, payload);
        assert_eq!(sha256(&recovered), hash);
    }

    #[test]
    fn sixty_three_columns_do_not_reconstruct_sixty_four_do() {
        let payload = vec![3u8; 8_192];
        let (shard_len, hash, shards) = encode_payload_shards(&payload).unwrap();
        let msgs: Vec<ColumnShardMessage> = shards
            .into_iter()
            .enumerate()
            .map(|(i, data)| ColumnShardMessage {
                index: i as u16,
                payload_len: payload.len() as u64,
                shard_len: shard_len as u64,
                payload_hash: hash,
                data,
            })
            .collect();
        let take = |n: usize| -> Vec<(usize, Vec<u8>)> {
            msgs.iter()
                .take(n)
                .map(|m| (m.index as usize, m.data.clone()))
                .collect()
        };
        assert!(decode_payload(payload.len(), shard_len, &hash, &take(63)).is_err());
        let (recovered, _) = decode_payload(payload.len(), shard_len, &hash, &take(64)).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn sixty_three_shards_fail() {
        let payload = vec![7u8; 10_000];
        let (shard_len, hash, shards) = encode_payload_shards(&payload).unwrap();
        let indexed: Vec<(usize, Vec<u8>)> = shards
            .iter()
            .enumerate()
            .take(63)
            .map(|(i, s)| (i, s.clone()))
            .collect();
        assert!(decode_payload(payload.len(), shard_len, &hash, &indexed).is_err());
    }

    #[test]
    fn custom_rate_round_trips_from_exactly_data_shards() {
        let params = RsParams::new(32, 48).unwrap();
        assert_eq!(params.parity(), 16);
        let payload: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        let (shard_len, hash, shards) = encode_payload_shards_with(&payload, params).unwrap();
        assert_eq!(shards.len(), 48);
        assert_eq!(shard_len, payload.len().div_ceil(32));

        // Drop the 32 systematic shards entirely: parity alone must decode.
        let kept: Vec<(usize, Vec<u8>)> = shards
            .iter()
            .enumerate()
            .skip(16)
            .take(32)
            .map(|(i, s)| (i, s.clone()))
            .collect();
        let (recovered, full) =
            decode_payload_with(payload.len(), shard_len, &hash, &kept, params).unwrap();
        assert_eq!(recovered, payload);
        assert_eq!(full.len(), 48);
    }

    #[test]
    fn custom_rate_fails_one_shard_below_the_threshold() {
        let params = RsParams::new(32, 48).unwrap();
        let payload = vec![9u8; 4_096];
        let (shard_len, hash, shards) = encode_payload_shards_with(&payload, params).unwrap();
        let kept: Vec<(usize, Vec<u8>)> = shards
            .iter()
            .enumerate()
            .take(31)
            .map(|(i, s)| (i, s.clone()))
            .collect();
        assert!(decode_payload_with(payload.len(), shard_len, &hash, &kept, params).is_err());
    }

    #[test]
    fn default_helpers_delegate_to_the_default_rate() {
        let payload = vec![5u8; 2_048];
        let from_default = encode_payload_shards(&payload).unwrap();
        let explicit = encode_payload_shards_with(&payload, RsParams::DEFAULT).unwrap();
        assert_eq!(from_default, explicit);
        assert_eq!(RsParams::default(), RsParams::DEFAULT);
        assert_eq!(RsParams::DEFAULT.parity(), PAYLOAD_PARITY_SHARDS);
    }

    #[test]
    fn invalid_rates_are_rejected() {
        for (data, total) in [
            (0, 10),                     // no data shards
            (10, 10),                    // no parity shards
            (10, 9),                     // total below data
            (1, MAX_TOTAL_SHARDS + 1),   // beyond GF(2^8)
        ] {
            assert!(
                matches!(
                    RsParams::new(data, total),
                    Err(PayloadCodingError::InvalidRsParams { .. })
                ),
                "{data}-of-{total} must be rejected"
            );
        }
        assert!(RsParams::new(1, MAX_TOTAL_SHARDS).is_ok());
        // The GF(2^8) bound is exactly what reed-solomon-erasure enforces.
        assert!(encode_payload_shards_with(
            &[1u8; 64],
            RsParams {
                data: 1,
                total: MAX_TOTAL_SHARDS + 1
            }
        )
        .is_err());
    }

    #[test]
    fn empty_payload_rejected() {
        assert!(matches!(
            encode_payload_shards(&[]),
            Err(PayloadCodingError::EmptyPayload)
        ));
    }

    #[test]
    fn hash_mismatch_detected() {
        let payload = vec![1u8; 5_000];
        let (shard_len, _hash, shards) = encode_payload_shards(&payload).unwrap();
        let wrong_hash = [0xAAu8; 32];
        let indexed: Vec<(usize, Vec<u8>)> = shards
            .iter()
            .enumerate()
            .take(64)
            .map(|(i, s)| (i, s.clone()))
            .collect();
        assert!(matches!(
            decode_payload(payload.len(), shard_len, &wrong_hash, &indexed),
            Err(PayloadCodingError::HashMismatch)
        ));
    }
}
