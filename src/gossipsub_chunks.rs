//! Raw payload chunking for normal Gossipsub messages.
//!
//! Unlike the Reed-Solomon modes, every chunk is required to reconstruct the
//! original payload. Each chunk commits to the full payload hash and layout.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_ASSEMBLIES: usize = 4;

/// One normal-Gossipsub message carrying a contiguous payload chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipsubChunkMessage {
    pub payload_len: u64,
    pub payload_hash: [u8; 32],
    pub index: u32,
    pub chunk_count: u32,
    pub data: Vec<u8>,
}

impl GossipsubChunkMessage {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize gossipsub chunk")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkError {
    ZeroChunkCount,
    TooManyChunks,
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroChunkCount => write!(f, "chunk count must be positive"),
            Self::TooManyChunks => write!(f, "chunk count exceeds the wire format limit"),
        }
    }
}

impl std::error::Error for ChunkError {}

fn hash(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

fn effective_chunk_count(payload_len: usize, configured_count: usize) -> Result<usize, ChunkError> {
    if configured_count == 0 {
        return Err(ChunkError::ZeroChunkCount);
    }
    let count = configured_count.min(payload_len.max(1));
    u32::try_from(count).map_err(|_| ChunkError::TooManyChunks)?;
    Ok(count)
}

fn expected_chunk_len(payload_len: usize, chunk_count: usize, index: usize) -> Option<usize> {
    if chunk_count == 0 || index >= chunk_count {
        return None;
    }
    let chunk_len = payload_len.div_ceil(chunk_count);
    let start = chunk_len.checked_mul(index)?;
    Some(payload_len.saturating_sub(start).min(chunk_len))
}

/// Split `payload` into up to `configured_count` non-empty contiguous chunks.
/// An empty payload is represented by one empty chunk.
pub fn split_payload(
    payload: &[u8],
    configured_count: usize,
) -> Result<Vec<GossipsubChunkMessage>, ChunkError> {
    let chunk_count = effective_chunk_count(payload.len(), configured_count)?;
    let chunk_len = payload.len().div_ceil(chunk_count);
    let payload_hash = hash(payload);
    let mut chunks = Vec::with_capacity(chunk_count);

    for index in 0..chunk_count {
        let start = chunk_len * index;
        let end = start.saturating_add(chunk_len).min(payload.len());
        chunks.push(GossipsubChunkMessage {
            payload_len: payload.len() as u64,
            payload_hash,
            index: index as u32,
            chunk_count: chunk_count as u32,
            data: payload[start..end].to_vec(),
        });
    }
    Ok(chunks)
}

struct Assembly {
    payload_len: usize,
    chunk_count: usize,
    chunks: HashMap<usize, Vec<u8>>,
}

/// Result from accepting one chunk into an assembler.
pub struct ChunkMergeOutcome {
    pub added: bool,
    pub distinct: usize,
    pub payload: Option<Vec<u8>>,
}

/// Collects chunks for a small number of concurrently propagated payloads.
pub struct GossipsubChunkAssembler {
    assemblies: HashMap<[u8; 32], Assembly>,
}

impl GossipsubChunkAssembler {
    pub fn new() -> Self {
        Self {
            assemblies: HashMap::new(),
        }
    }

    /// Validate and merge a chunk. Invalid messages and duplicate indices are
    /// ignored. A payload is returned only after every chunk is present and its
    /// SHA-256 commitment matches.
    pub fn merge(&mut self, message: GossipsubChunkMessage) -> ChunkMergeOutcome {
        let invalid = || ChunkMergeOutcome {
            added: false,
            distinct: 0,
            payload: None,
        };
        let Ok(payload_len) = usize::try_from(message.payload_len) else {
            return invalid();
        };
        let chunk_count = message.chunk_count as usize;
        let index = message.index as usize;
        if chunk_count == 0
            || chunk_count > payload_len.max(1)
            || index >= chunk_count
            || expected_chunk_len(payload_len, chunk_count, index) != Some(message.data.len())
        {
            return invalid();
        }

        let payload_hash = message.payload_hash;
        if !self.assemblies.contains_key(&payload_hash) {
            if self.assemblies.len() == MAX_ASSEMBLIES {
                return invalid();
            }
            self.assemblies.insert(
                payload_hash,
                Assembly {
                    payload_len,
                    chunk_count,
                    chunks: HashMap::new(),
                },
            );
        }

        let Some(assembly) = self.assemblies.get_mut(&payload_hash) else {
            return invalid();
        };
        if assembly.payload_len != payload_len || assembly.chunk_count != chunk_count {
            return invalid();
        }
        let added = if assembly.chunks.contains_key(&index) {
            false
        } else {
            assembly.chunks.insert(index, message.data);
            true
        };
        let distinct = assembly.chunks.len();
        if distinct != chunk_count {
            return ChunkMergeOutcome {
                added,
                distinct,
                payload: None,
            };
        }

        let mut payload = Vec::with_capacity(payload_len);
        for index in 0..chunk_count {
            let Some(chunk) = assembly.chunks.get(&index) else {
                return invalid();
            };
            payload.extend_from_slice(chunk);
        }
        self.assemblies.remove(&payload_hash);
        if payload.len() != payload_len || hash(&payload) != payload_hash {
            return ChunkMergeOutcome {
                added,
                distinct,
                payload: None,
            };
        }
        ChunkMergeOutcome {
            added,
            distinct,
            payload: Some(payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_reassembles_sixty_four_chunks() {
        let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let mut chunks = split_payload(&payload, 64).unwrap();
        assert_eq!(chunks.len(), 64);

        let mut assembler = GossipsubChunkAssembler::new();
        let mut recovered = None;
        while let Some(chunk) = chunks.pop() {
            recovered = assembler.merge(chunk).payload.or(recovered);
        }
        assert_eq!(recovered, Some(payload));
    }

    #[test]
    fn uneven_chunks_cover_the_payload() {
        let chunks = split_payload(b"abcdefghij", 3).unwrap();
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.data.len())
                .collect::<Vec<_>>(),
            [4, 4, 2]
        );
    }

    #[test]
    fn count_is_capped_to_non_empty_chunks() {
        let chunks = split_payload(b"abc", 64).unwrap();
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|chunk| !chunk.data.is_empty()));
    }

    #[test]
    fn incomplete_duplicate_and_malformed_chunks_do_not_reconstruct() {
        let chunks = split_payload(b"abcdefgh", 4).unwrap();
        let mut assembler = GossipsubChunkAssembler::new();
        assert!(assembler.merge(chunks[0].clone()).added);
        assert!(!assembler.merge(chunks[0].clone()).added);

        let mut malformed = chunks[1].clone();
        malformed.index = malformed.chunk_count;
        assert!(!assembler.merge(malformed).added);

        assert!(assembler.merge(chunks[1].clone()).payload.is_none());
        assert!(assembler.merge(chunks[2].clone()).payload.is_none());
    }

    #[test]
    fn hash_mismatch_is_rejected() {
        let mut chunks = split_payload(b"abcdefgh", 2).unwrap();
        chunks[1].data[0] ^= 1;
        let mut assembler = GossipsubChunkAssembler::new();
        assert!(assembler.merge(chunks.remove(0)).payload.is_none());
        assert!(assembler.merge(chunks.remove(0)).payload.is_none());
    }

    #[test]
    fn zero_chunk_count_is_rejected() {
        assert_eq!(
            split_payload(b"payload", 0),
            Err(ChunkError::ZeroChunkCount)
        );
    }
}
