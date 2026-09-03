//! Gossipsub 1.3 partial-message path for Reed-Solomon payload shards.
//!
//! Builder seeds each of 128 shards to 4 mesh peers via [`assign_chunk_recipients`].
//! Relays serve whatever they hold. Reconstruction is in [`crate::coding`].

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use libp2p::gossipsub::partial_messages::{Metadata, Partial, PartialAction, PartialError};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::coding::{decode_payload, PAYLOAD_DATA_SHARDS, PAYLOAD_TOTAL_SHARDS};

/// Version byte prefixing a payload-chunk group id (`0x01 || payload_hash`).
pub const PARTIAL_PAYLOAD_VERSION_BYTE: u8 = 0x01;


/// A growable-length bitmap. Backing storage is `ceil(len / 8)` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellBitmap {
    len: usize,
    bits: Vec<u8>,
}

impl CellBitmap {
    pub fn with_len(len: usize) -> Self {
        Self {
            len,
            bits: vec![0u8; len.div_ceil(8)],
        }
    }

    pub fn all_set(len: usize) -> Self {
        let mut b = Self::with_len(len);
        for i in 0..len {
            b.set(i);
        }
        b
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn get(&self, idx: usize) -> bool {
        if idx >= self.len {
            return false;
        }
        (self.bits[idx / 8] >> (idx % 8)) & 1 == 1
    }

    pub fn set(&mut self, idx: usize) {
        if idx < self.len {
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    pub fn num_set_bits(&self) -> usize {
        (0..self.len).filter(|&i| self.get(i)).count()
    }

    pub fn is_full(&self) -> bool {
        self.num_set_bits() == self.len
    }

    pub fn union(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for i in 0..self.len.min(other.len) {
            if other.get(i) {
                out.set(i);
            }
        }
        out
    }

    pub fn difference(&self, other: &Self) -> Self {
        let mut out = Self::with_len(self.len);
        for i in 0..self.len {
            if self.get(i) && !other.get(i) {
                out.set(i);
            }
        }
        out
    }

    pub fn intersection(&self, other: &Self) -> Self {
        let mut out = Self::with_len(self.len);
        for i in 0..self.len.min(other.len) {
            if self.get(i) && other.get(i) {
                out.set(i);
            }
        }
        out
    }

    pub fn is_subset(&self, other: &Self) -> bool {
        (0..self.len).all(|i| !self.get(i) || other.get(i))
    }
}

/// Per-peer metadata: which shards the peer has (`available`) and wants (`requests`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadChunkPartsMetadata {
    pub available: CellBitmap,
    pub requests: CellBitmap,
}

impl PayloadChunkPartsMetadata {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize parts metadata")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Header carried once per payload group: the pieces needed to verify
/// reconstruction and identify the payload. Sent only in the first
/// (header-bearing) partial message a peer receives for a payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadChunkHeader {
    /// Exact (unpadded) payload length in bytes.
    pub payload_len: u64,
    /// `ceil(payload_len / PAYLOAD_DATA_SHARDS)` — every shard's byte length.
    pub shard_len: u64,
    /// SHA-256 of the exact payload, verified after reconstruction.
    pub payload_hash: [u8; 32],
}

impl PayloadChunkHeader {
    pub fn new(
        payload_len: usize,
        shard_len: usize,
        payload_hash: [u8; 32],
    ) -> Self {
        Self {
            payload_len: payload_len as u64,
            shard_len: shard_len as u64,
            payload_hash,
        }
    }
}

/// A sparse, partial set of a payload's 128 shards: only the shards currently
/// held, with a bitmap marking which indices are present. Optionally carries
/// the header (only the first message a peer receives for a payload includes
/// it). Structurally mirrors `PartialDataColumnSidecar` in `types.rs`, but one
/// payload has a single flat 128-shard array rather than a blob × column
/// matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialPayloadChunks {
    /// One bit per shard index (0..128): set when that shard is present.
    pub shards_present_bitmap: CellBitmap,
    /// The present shards, in ascending index order (sparse storage).
    pub shards: Vec<Vec<u8>>,
    /// Header, sent only in the first (header-bearing) message.
    pub header: Option<PayloadChunkHeader>,
}

impl PartialPayloadChunks {
    /// An empty set (no shards), optionally carrying a header. Used for the
    /// relay phase-1 header-only message.
    pub fn empty(header: Option<PayloadChunkHeader>) -> Self {
        Self {
            shards_present_bitmap: CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS),
            shards: Vec::new(),
            header,
        }
    }

    pub fn num_present(&self) -> usize {
        self.shards_present_bitmap.num_set_bits()
    }

    /// Whether the bitmap and sparse shard vector are internally consistent
    /// (present-count matches storage length). Per-shard length consistency
    /// is checked separately by the assembler once the header (and its
    /// `shard_len`) is known.
    pub fn is_structurally_valid(&self) -> bool {
        self.shards.len() == self.num_present()
    }

    pub fn is_complete(&self) -> bool {
        self.shards_present_bitmap.is_full()
    }

    /// Fetch the shard at index `idx`, translating the bitmap position to the
    /// sparse storage position.
    pub fn get(&self, idx: usize) -> Option<&Vec<u8>> {
        if !self.shards_present_bitmap.get(idx) {
            return None;
        }
        let storage_idx = (0..idx)
            .filter(|&i| self.shards_present_bitmap.get(i))
            .count();
        self.shards.get(storage_idx)
    }

    /// Build a new set containing only the present shards for which
    /// `keep(idx)` is true. The header is dropped (deltas never carry it).
    pub fn filter<F: Fn(usize) -> bool>(&self, keep: F) -> Self {
        let mut bitmap = CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS);
        let mut shards = Vec::new();
        for idx in 0..PAYLOAD_TOTAL_SHARDS {
            if self.shards_present_bitmap.get(idx) && keep(idx) {
                if let Some(shard) = self.get(idx) {
                    bitmap.set(idx);
                    shards.push(shard.clone());
                }
            }
        }
        Self {
            shards_present_bitmap: bitmap,
            shards,
            header: None,
        }
    }

    /// Encode for the wire using the simulator's compact binary codec.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize partial payload chunks")
    }

    /// Decode from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

// ---------------------------------------------------------------------------
// Group id helpers
// ---------------------------------------------------------------------------

/// Build the gossipsub partial-message group id for a payload:
/// `0x01 || payload_hash`.
pub fn payload_group_id(payload_hash: &[u8; 32]) -> Vec<u8> {
    let mut id = Vec::with_capacity(1 + 32);
    id.push(PARTIAL_PAYLOAD_VERSION_BYTE);
    id.extend_from_slice(payload_hash);
    id
}

/// Recover the payload hash from a group id built by [`payload_group_id`].
pub fn payload_hash_from_group_id(group_id: &[u8]) -> Option<[u8; 32]> {
    if group_id.len() != 1 + 32 || group_id[0] != PARTIAL_PAYLOAD_VERSION_BYTE {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&group_id[1..33]);
    Some(hash)
}

// ---------------------------------------------------------------------------
// Deterministic peer assignment
// ---------------------------------------------------------------------------

/// Deterministically assign each of the 128 shards to `recipients_per_shard`
/// distinct peers ranked out of `mesh_peers`, using
/// `sha256(payload_hash || shard_index_le || peer_bytes)` as the rank key —
/// no `thread_rng`/OS entropy, so the same seed/payload/mesh always produces
/// the same assignment. Returns a map from every peer in `mesh_peers` to the
/// (possibly empty) set of shard indices assigned to it.
///
/// If `mesh_peers.len() < recipients_per_shard`, every available peer is
/// assigned every shard (the caller should record the *actual* replication
/// factor achieved, e.g. via an event).
pub fn assign_chunk_recipients(
    payload_hash: &[u8; 32],
    mesh_peers: &[PeerId],
    recipients_per_shard: usize,
) -> HashMap<PeerId, CellBitmap> {
    let mut assignment: HashMap<PeerId, CellBitmap> = mesh_peers
        .iter()
        .map(|&peer| (peer, CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS)))
        .collect();
    if mesh_peers.is_empty() {
        return assignment;
    }
    let take = recipients_per_shard.min(mesh_peers.len());
    for shard_idx in 0..PAYLOAD_TOTAL_SHARDS {
        let mut ranked: Vec<(u64, PeerId)> = mesh_peers
            .iter()
            .map(|&peer| (rank_key(payload_hash, shard_idx, &peer), peer))
            .collect();
        ranked.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.to_bytes().cmp(&b.1.to_bytes()))
        });
        for &(_, peer) in ranked.iter().take(take) {
            assignment
                .get_mut(&peer)
                .expect("peer present in initial map")
                .set(shard_idx);
        }
    }
    assignment
}

/// Deterministic rank key for `(payload_hash, shard_idx, peer)`.
fn rank_key(payload_hash: &[u8; 32], shard_idx: usize, peer: &PeerId) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(payload_hash);
    hasher.update((shard_idx as u32).to_le_bytes());
    hasher.update(peer.to_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"))
}

// ---------------------------------------------------------------------------
// Per-peer metadata (gossipsub `Metadata` impl)
// ---------------------------------------------------------------------------

/// Per-peer partial metadata for the chunk protocol, tracked as either
/// not-yet-known or known. Mirrors `partial.rs::MaybeKnownMetadata` for data
/// columns: `update` unions a peer's advertised bitmaps into our view (bits
/// only ever grow), and `update_from_data` folds in what a peer learns from a
/// body we sent it.
#[derive(Debug, Clone)]
pub enum PayloadChunkMetadata {
    Unknown,
    Known {
        metadata: PayloadChunkPartsMetadata,
        encoded: Vec<u8>,
    },
}

impl PayloadChunkMetadata {
    fn known(metadata: PayloadChunkPartsMetadata) -> Self {
        let encoded = metadata.encode();
        Self::Known { metadata, encoded }
    }

    fn do_update(&mut self, incoming: PayloadChunkPartsMetadata) -> bool {
        match self {
            Self::Unknown => {
                *self = Self::known(incoming);
                true
            }
            Self::Known { metadata, .. } => {
                let merged = PayloadChunkPartsMetadata {
                    available: metadata.available.union(&incoming.available),
                    requests: metadata.requests.union(&incoming.requests),
                };
                if merged == *metadata {
                    false
                } else {
                    *self = Self::known(merged);
                    true
                }
            }
        }
    }
}

impl From<PayloadChunkPartsMetadata> for PayloadChunkMetadata {
    fn from(metadata: PayloadChunkPartsMetadata) -> Self {
        Self::known(metadata)
    }
}

impl Metadata for PayloadChunkMetadata {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Unknown => &[],
            Self::Known { encoded, .. } => encoded,
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<bool, PartialError> {
        let received =
            PayloadChunkPartsMetadata::decode(data).map_err(|_| PartialError::InvalidFormat)?;
        Ok(self.do_update(received))
    }

    fn update_from_data(&mut self, data: &[u8]) -> Result<(), PartialError> {
        if data.is_empty() {
            return Ok(());
        }
        let chunks = PartialPayloadChunks::decode(data).map_err(|_| PartialError::InvalidFormat)?;
        // A peer that received these shards now both has them and (implicitly)
        // requested them.
        self.do_update(PayloadChunkPartsMetadata {
            available: chunks.shards_present_bitmap.clone(),
            requests: chunks.shards_present_bitmap,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Outgoing partial payload (gossipsub `Partial` impl)
// ---------------------------------------------------------------------------

/// The set of peers we have already sent a header-bearing message to, for one
/// payload. Shared across every `OutgoingPayloadChunks` instance for the same
/// payload (builder seeding and later relay republishes), so the header is
/// sent to each peer at most once.
pub type HeaderSentSet = Arc<Mutex<std::collections::HashSet<PeerId>>>;

/// Bounded map from payload hash to its shared [`HeaderSentSet`], so every
/// republish of the same payload shares one "have we sent this peer the
/// header?" set. Evicts the oldest payload once `capacity` is exceeded.
/// Mirrors `partial::PartialColumnHeaderTracker`.
pub struct PayloadChunkHeaderTracker {
    capacity: usize,
    order: VecDeque<[u8; 32]>,
    sets: HashMap<[u8; 32], HeaderSentSet>,
}

impl PayloadChunkHeaderTracker {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            sets: HashMap::new(),
        }
    }

    /// Fetch (or create) the shared header-sent set for a payload.
    pub fn get_for_payload(&mut self, payload_hash: [u8; 32]) -> HeaderSentSet {
        if let Some(set) = self.sets.get(&payload_hash) {
            return Arc::clone(set);
        }
        if self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.sets.remove(&old);
            }
        }
        let set: HeaderSentSet = Arc::new(Mutex::new(std::collections::HashSet::new()));
        self.sets.insert(payload_hash, Arc::clone(&set));
        self.order.push_back(payload_hash);
        set
    }
}

/// A set of payload shards we are publishing via the partial protocol.
///
/// Two roles, selected by `initial_assignment`:
///   - **Seeder** (builder, `initial_assignment: Some(..)`): on first contact
///     with an assigned peer, sends the header plus that peer's assigned
///     shards in one message. On every later round, sends only shards that
///     are both requested-and-missing *and* within that peer's original
///     assignment — a seeder never serves a peer a shard it wasn't assigned,
///     even if the peer's `requests` bitmap (which defaults to "all") asks
///     for more.
///   - **Relay** (`initial_assignment: None`): behaves exactly like the
///     existing data-column path — header-only on first contact, then
///     eagerly fulfils whatever the peer requests and lacks, out of
///     whatever this node currently holds.
#[derive(Debug, Clone)]
pub struct OutgoingPayloadChunks {
    /// The payload's header, always known at construction time — stored
    /// directly (rather than read from `chunks.header`, which may be absent
    /// on a bare snapshot) so `group_id()` is always well-defined.
    header: PayloadChunkHeader,
    chunks: Arc<PartialPayloadChunks>,
    metadata: PayloadChunkMetadata,
    header_message: Vec<u8>,
    header_sent_set: HeaderSentSet,
    initial_assignment: Option<Arc<HashMap<PeerId, CellBitmap>>>,
}

impl OutgoingPayloadChunks {
    /// Build an outgoing set of shards. `requests` are the shards we still
    /// want from peers; we always also mark shards we already hold as
    /// requested, so our advertised `requests ⊇ available` (matches the
    /// data-column convention).
    ///
    /// `initial_assignment`, when set, restricts what this instance will ever
    /// send to a given peer to that peer's entry (see the struct docs).
    pub fn new(
        chunks: Arc<PartialPayloadChunks>,
        header: &PayloadChunkHeader,
        header_sent_set: HeaderSentSet,
        requests: CellBitmap,
        initial_assignment: Option<Arc<HashMap<PeerId, CellBitmap>>>,
    ) -> Self {
        let available = chunks.shards_present_bitmap.clone();
        let requests = requests.union(&available);
        let metadata = PayloadChunkMetadata::from(PayloadChunkPartsMetadata {
            available: available.clone(),
            requests,
        });
        let header_message = PartialPayloadChunks::empty(Some(header.clone())).encode();
        Self {
            header: header.clone(),
            chunks,
            metadata,
            header_message,
            header_sent_set,
            initial_assignment,
        }
    }

    /// This instance's cap for `peer_id`: its original shard assignment if
    /// this is a seeder and the peer was assigned any shards, or "no
    /// restriction" for a relay / an unassigned peer (e.g. one reached only
    /// via heartbeat gossip-lazy amplification rather than the initial mesh
    /// snapshot).
    fn send_cap(&self, peer_id: &PeerId) -> CellBitmap {
        match self
            .initial_assignment
            .as_ref()
            .and_then(|m| m.get(peer_id))
        {
            Some(assigned) => assigned.clone(),
            None => CellBitmap::all_set(PAYLOAD_TOTAL_SHARDS),
        }
    }
}

impl Partial for OutgoingPayloadChunks {
    fn group_id(&self) -> Vec<u8> {
        payload_group_id(&self.header.payload_hash)
    }

    fn metadata(&self) -> Box<dyn Metadata> {
        Box::new(self.metadata.clone())
    }

    fn partial_action_from_metadata(
        &self,
        peer_id: PeerId,
        metadata: Option<&[u8]>,
    ) -> Result<PartialAction, PartialError> {
        match metadata {
            // Phase 1: peer has no metadata yet.
            None => {
                let first_time = self
                    .header_sent_set
                    .lock()
                    .expect("header set poisoned")
                    .insert(peer_id);
                if !first_time {
                    return Ok(PartialAction {
                        need: false,
                        send: None,
                    });
                }
                let assigned = self
                    .initial_assignment
                    .as_ref()
                    .and_then(|m| m.get(&peer_id));
                let send = match assigned {
                    // Seeder with an assignment for this peer: header + its
                    // assigned shards in one message (saves a round trip).
                    Some(assigned) if assigned.num_set_bits() > 0 => {
                        let mut body = self.chunks.filter(|idx| assigned.get(idx));
                        body.header = Some(self.header.clone());
                        let sent_meta = PayloadChunkMetadata::from(PayloadChunkPartsMetadata {
                            available: assigned.clone(),
                            requests: assigned.clone(),
                        });
                        Some((body.encode(), Box::new(sent_meta) as Box<dyn Metadata>))
                    }
                    // Relay, or a seeder with no assignment for this peer
                    // (e.g. reached only via heartbeat amplification):
                    // header-only, matching the data-column phase-1 flow.
                    _ => Some((
                        self.header_message.clone(),
                        Box::new(PayloadChunkMetadata::Unknown) as Box<dyn Metadata>,
                    )),
                };
                Ok(PartialAction { need: false, send })
            }
            // Empty metadata: nothing to do.
            Some([]) => Ok(PartialAction {
                need: false,
                send: None,
            }),
            // Phase 3: peer advertised metadata → send the shards it wants
            // but lacks, capped to this peer's assignment if we are a seeder.
            Some(bytes) => {
                self.header_sent_set
                    .lock()
                    .expect("header set poisoned")
                    .insert(peer_id);

                let peer_meta = PayloadChunkPartsMetadata::decode(bytes)
                    .map_err(|_| PartialError::InvalidFormat)?;

                let ours = &self.chunks.shards_present_bitmap;
                let need = !peer_meta.available.is_subset(ours);

                let cap = self.send_cap(&peer_id);
                let want = peer_meta
                    .requests
                    .difference(&peer_meta.available)
                    .intersection(&cap);
                let filtered = self.chunks.filter(|idx| want.get(idx));

                let send = if filtered.num_present() == 0 {
                    None
                } else {
                    let updated = PayloadChunkPartsMetadata {
                        available: peer_meta.available.union(&filtered.shards_present_bitmap),
                        requests: peer_meta.requests.union(&filtered.shards_present_bitmap),
                    };
                    Some((
                        filtered.encode(),
                        Box::new(PayloadChunkMetadata::from(updated)) as Box<dyn Metadata>,
                    ))
                };

                Ok(PartialAction { need, send })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Assembler (accumulate received shards, reconstruct at the 64-shard threshold)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadState {
    Collecting,
    Reconstructing,
    Complete,
    /// Reconstruction was attempted and failed (hash mismatch or an RS
    /// error); further shards may still arrive and a retry is possible.
    Failed,
}

struct PayloadAssembly {
    generation: u64,
    header: Option<PayloadChunkHeader>,
    bitmap: CellBitmap,
    shards: Vec<Option<Vec<u8>>>,
    state: PayloadState,
}

/// Outcome of merging one received set of shards into the assembler.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeOutcome {
    /// Genuinely new distinct shards this merge added.
    pub added_shards: usize,
    /// Total distinct shards held after this merge.
    pub distinct_shards: usize,
    /// Whether this merge just crossed the 64-shard reconstruction threshold
    /// (and the payload was not already reconstructing/complete).
    pub crossed_threshold: bool,
}

/// Accumulates received payload shards per payload hash (bounded FIFO
/// capacity, mirroring `partial::PartialColumnAssembler`) and reconstructs
/// once 64 distinct shards are held.
pub struct PayloadChunkAssembler {
    capacity: usize,
    order: VecDeque<[u8; 32]>,
    payloads: HashMap<[u8; 32], PayloadAssembly>,
    next_generation: u64,
}

impl PayloadChunkAssembler {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            payloads: HashMap::new(),
            next_generation: 1,
        }
    }

    fn ensure(&mut self, payload_hash: [u8; 32]) -> &mut PayloadAssembly {
        if !self.payloads.contains_key(&payload_hash) {
            if self.order.len() >= self.capacity {
                if let Some(old) = self.order.pop_front() {
                    self.payloads.remove(&old);
                }
            }
            self.order.push_back(payload_hash);
            let generation = self.next_generation;
            self.next_generation = self.next_generation.wrapping_add(1).max(1);
            self.payloads.insert(
                payload_hash,
                PayloadAssembly {
                    generation,
                    header: None,
                    bitmap: CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS),
                    shards: vec![None; PAYLOAD_TOTAL_SHARDS],
                    state: PayloadState::Collecting,
                },
            );
        }
        self.payloads.get_mut(&payload_hash).expect("just inserted")
    }

    /// Record a payload's header (idempotent; keeps the first one seen).
    pub fn set_header(&mut self, payload_hash: [u8; 32], header: PayloadChunkHeader) {
        let assembly = self.ensure(payload_hash);
        if assembly.header.is_none() {
            assembly.header = Some(header);
        }
    }

    pub fn get_header(&self, payload_hash: &[u8; 32]) -> Option<PayloadChunkHeader> {
        self.payloads.get(payload_hash)?.header.clone()
    }

    pub fn generation(&self, payload_hash: &[u8; 32]) -> Option<u64> {
        self.payloads.get(payload_hash).map(|a| a.generation)
    }

    pub fn is_complete(&self, payload_hash: &[u8; 32]) -> bool {
        self.payloads
            .get(payload_hash)
            .is_some_and(|a| a.state == PayloadState::Complete)
    }

    #[allow(dead_code)]
    pub fn distinct_shards(&self, payload_hash: &[u8; 32]) -> usize {
        self.payloads
            .get(payload_hash)
            .map(|a| a.bitmap.num_set_bits())
            .unwrap_or(0)
    }

    /// Merge a received set of shards into the assembly for `payload_hash`
    /// (the caller always knows this from the gossipsub partial-message group
    /// id — `payload_hash_from_group_id` — regardless of whether this
    /// particular message carries the header). Rejects structurally invalid
    /// input. Once the payload has crossed into
    /// `Reconstructing`/`Complete`/`Failed`, further merges are accepted (so
    /// a failed reconstruction can still gather more shards) but do not
    /// re-trigger `crossed_threshold`.
    pub fn merge_partial(
        &mut self,
        payload_hash: [u8; 32],
        chunks: &PartialPayloadChunks,
    ) -> MergeOutcome {
        if !chunks.is_structurally_valid() {
            return MergeOutcome::default();
        }
        if let Some(header) = &chunks.header {
            self.set_header(payload_hash, header.clone());
        }
        let assembly = self.ensure(payload_hash);
        let already_past_collecting = assembly.state != PayloadState::Collecting;
        let expected_shard_len = assembly.header.as_ref().map(|h| h.shard_len as usize);

        let mut added = 0;
        for idx in 0..PAYLOAD_TOTAL_SHARDS {
            if !chunks.shards_present_bitmap.get(idx) || assembly.bitmap.get(idx) {
                continue;
            }
            let Some(shard) = chunks.get(idx) else {
                continue;
            };
            if let Some(expected) = expected_shard_len {
                if shard.len() != expected {
                    continue;
                }
            }
            assembly.bitmap.set(idx);
            assembly.shards[idx] = Some(shard.clone());
            added += 1;
        }
        let distinct = assembly.bitmap.num_set_bits();
        let crossed = added > 0 && !already_past_collecting && distinct >= PAYLOAD_DATA_SHARDS;
        if crossed {
            assembly.state = PayloadState::Reconstructing;
        }
        MergeOutcome {
            added_shards: added,
            distinct_shards: distinct,
            crossed_threshold: crossed,
        }
    }

    /// Attempt reconstruction for `payload_hash`, guarded by `generation`
    /// (a delayed reconstruction job whose payload was evicted, or whose
    /// assembly was replaced, becomes a no-op). On success, stores the full
    /// 128-shard set (so this node can serve any peer afterward) and marks
    /// the assembly complete. On failure (should only happen if shards were
    /// corrupted, which the simulator does not model), marks it `Failed` and
    /// returns `None` so the caller can emit a diagnostic event.
    pub fn reconstruct(&mut self, payload_hash: [u8; 32], generation: u64) -> Option<Vec<u8>> {
        let assembly = self.payloads.get_mut(&payload_hash)?;
        if assembly.generation != generation || assembly.state == PayloadState::Complete {
            return None;
        }
        let header = assembly.header.clone()?;
        let present: Vec<(usize, Vec<u8>)> = assembly
            .shards
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.clone().map(|d| (i, d)))
            .collect();
        match decode_payload(
            header.payload_len as usize,
            header.shard_len as usize,
            &header.payload_hash,
            &present,
        ) {
            Ok((payload, shards)) => {
                for (i, shard) in shards.into_iter().enumerate() {
                    assembly.shards[i] = Some(shard);
                    assembly.bitmap.set(i);
                }
                assembly.state = PayloadState::Complete;
                Some(payload)
            }
            Err(_) => {
                assembly.state = PayloadState::Failed;
                None
            }
        }
    }

    /// Snapshot the currently-held shards as a [`PartialPayloadChunks`], for
    /// republishing/serving to other peers.
    pub fn current_partial(&self, payload_hash: &[u8; 32]) -> Option<PartialPayloadChunks> {
        let assembly = self.payloads.get(payload_hash)?;
        let mut bitmap = CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS);
        let mut shards = Vec::new();
        for (idx, shard) in assembly.shards.iter().enumerate() {
            if let Some(shard) = shard {
                bitmap.set(idx);
                shards.push(shard.clone());
            }
        }
        Some(PartialPayloadChunks {
            shards_present_bitmap: bitmap,
            shards,
            header: assembly.header.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::encode_payload_shards;

    fn peer(seed: u8) -> PeerId {
        // Deterministic PeerIds for assignment tests: derive from a keypair
        // seeded by a single byte, matching the simulator's ban on
        // `thread_rng`/OS entropy elsewhere.
        use libp2p::identity::Keypair;
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        PeerId::from(Keypair::ed25519_from_bytes(bytes).unwrap().public())
    }

    // -- Deterministic peer assignment --

    #[test]
    fn assignment_gives_exactly_min_configured_eligible_recipients_per_shard() {
        let hash = [3u8; 32];
        let peers: Vec<PeerId> = (0..10).map(peer).collect();
        let assignment = assign_chunk_recipients(&hash, &peers, 4);
        // Every peer appears in the map, even if assigned nothing.
        assert_eq!(assignment.len(), 10);
        // Every shard index is assigned to exactly 4 peers.
        for shard_idx in 0..PAYLOAD_TOTAL_SHARDS {
            let count = assignment.values().filter(|b| b.get(shard_idx)).count();
            assert_eq!(
                count, 4,
                "shard {shard_idx} should have exactly 4 recipients"
            );
        }
    }

    #[test]
    fn assignment_falls_back_to_all_peers_when_fewer_than_configured() {
        let hash = [9u8; 32];
        let peers: Vec<PeerId> = (0..2).map(peer).collect();
        let assignment = assign_chunk_recipients(&hash, &peers, 4);
        for shard_idx in 0..PAYLOAD_TOTAL_SHARDS {
            let count = assignment.values().filter(|b| b.get(shard_idx)).count();
            assert_eq!(count, 2);
        }
    }

    #[test]
    fn assignment_is_deterministic_across_calls() {
        let hash = [5u8; 32];
        let peers: Vec<PeerId> = (0..12).map(peer).collect();
        let a = assign_chunk_recipients(&hash, &peers, 4);
        let b = assign_chunk_recipients(&hash, &peers, 4);
        assert_eq!(a, b);
    }

    #[test]
    fn different_shards_get_different_peer_sets() {
        let hash = [1u8; 32];
        let peers: Vec<PeerId> = (0..20).map(peer).collect();
        let assignment = assign_chunk_recipients(&hash, &peers, 4);
        let holders_for = |idx: usize| -> Vec<PeerId> {
            let mut v: Vec<PeerId> = assignment
                .iter()
                .filter(|(_, b)| b.get(idx))
                .map(|(&p, _)| p)
                .collect();
            v.sort_by_key(|p| p.to_bytes());
            v
        };
        // Not every shard should land on the exact same 4 peers.
        let first = holders_for(0);
        let differs = (1..PAYLOAD_TOTAL_SHARDS).any(|i| holders_for(i) != first);
        assert!(differs, "all shards assigned to the identical peer set");
    }

    // -- Assembler --

    fn header(payload_len: usize, shard_len: usize, hash: [u8; 32]) -> PayloadChunkHeader {
        PayloadChunkHeader::new(payload_len, shard_len, hash)
    }

    #[test]
    fn assembler_crosses_threshold_at_64_distinct_shards() {
        let payload = vec![9u8; 200_000];
        let (shard_len, hash, shards) = encode_payload_shards(&payload).unwrap();
        let mut assembler = PayloadChunkAssembler::new(4);
        assembler.set_header(hash, header(payload.len(), shard_len, hash));

        // Feed 63 shards one at a time: never crosses.
        for i in 0..63 {
            let body = PartialPayloadChunks {
                shards_present_bitmap: {
                    let mut b = CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS);
                    b.set(i);
                    b
                },
                shards: vec![shards[i].clone()],
                header: None,
            };
            let outcome = assembler.merge_partial(hash, &body);
            assert!(!outcome.crossed_threshold);
        }
        // 64th shard crosses.
        let body = PartialPayloadChunks {
            shards_present_bitmap: {
                let mut b = CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS);
                b.set(63);
                b
            },
            shards: vec![shards[63].clone()],
            header: None,
        };
        let outcome = assembler.merge_partial(hash, &body);
        assert!(outcome.crossed_threshold);
        assert_eq!(outcome.distinct_shards, 64);

        let generation = assembler.generation(&hash).unwrap();
        let recovered = assembler.reconstruct(hash, generation).unwrap();
        assert_eq!(recovered, payload);
        assert!(assembler.is_complete(&hash));

        // After reconstruction, this node holds and can serve all 128 shards.
        let full = assembler.current_partial(&hash).unwrap();
        assert!(full.is_complete());
        assert_eq!(full.shards.len(), PAYLOAD_TOTAL_SHARDS);
    }

    #[test]
    fn duplicate_shard_adds_zero_and_does_not_retrigger() {
        let payload = vec![1u8; 10_000];
        let (shard_len, hash, shards) = encode_payload_shards(&payload).unwrap();
        let mut assembler = PayloadChunkAssembler::new(4);
        assembler.set_header(hash, header(payload.len(), shard_len, hash));

        let mut bitmap = CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS);
        for i in 0..64 {
            bitmap.set(i);
        }
        let body = PartialPayloadChunks {
            shards_present_bitmap: bitmap,
            shards: shards[..64].to_vec(),
            header: None,
        };
        let first = assembler.merge_partial(hash, &body);
        assert!(first.crossed_threshold);
        assert_eq!(first.added_shards, 64);

        let second = assembler.merge_partial(hash, &body);
        assert_eq!(second.added_shards, 0);
        assert!(!second.crossed_threshold);
    }

    #[test]
    fn stale_generation_reconstruction_is_a_no_op() {
        let payload = vec![2u8; 10_000];
        let (shard_len, hash, shards) = encode_payload_shards(&payload).unwrap();
        let mut assembler = PayloadChunkAssembler::new(4);
        assembler.set_header(hash, header(payload.len(), shard_len, hash));
        let mut bitmap = CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS);
        for i in 0..64 {
            bitmap.set(i);
        }
        let body = PartialPayloadChunks {
            shards_present_bitmap: bitmap,
            shards: shards[..64].to_vec(),
            header: None,
        };
        assembler.merge_partial(hash, &body);
        let real_generation = assembler.generation(&hash).unwrap();
        assert!(assembler.reconstruct(hash, real_generation + 1).is_none());
        assert!(!assembler.is_complete(&hash));
    }

    #[test]
    fn eviction_isolates_old_payloads() {
        let mut assembler = PayloadChunkAssembler::new(2);
        let hashes: Vec<[u8; 32]> = (0..3u8).map(|i| [i; 32]).collect();
        for (i, h) in hashes.iter().enumerate() {
            assembler.set_header(*h, header(100, 2, *h));
            let _ = i;
        }
        // Capacity 2: the first payload should have been evicted.
        assert!(assembler.get_header(&hashes[0]).is_none());
        assert!(assembler.get_header(&hashes[1]).is_some());
        assert!(assembler.get_header(&hashes[2]).is_some());
    }

    #[test]
    fn malformed_body_rejected_by_structural_validity() {
        let bad = PartialPayloadChunks {
            shards_present_bitmap: CellBitmap::all_set(4),
            shards: vec![vec![0u8; 4]], // only 1 shard but bitmap claims 4
            header: None,
        };
        assert!(!bad.is_structurally_valid());
        let mut assembler = PayloadChunkAssembler::new(4);
        let outcome = assembler.merge_partial([7u8; 32], &bad);
        assert_eq!(outcome, MergeOutcome::default());
    }

    // -- Group id --

    #[test]
    fn group_id_round_trips() {
        let hash = [42u8; 32];
        let id = payload_group_id(&hash);
        assert_eq!(id[0], PARTIAL_PAYLOAD_VERSION_BYTE);
        assert_eq!(payload_hash_from_group_id(&id), Some(hash));
    }

    #[test]
    fn group_id_rejects_wrong_version_or_length() {
        assert_eq!(payload_hash_from_group_id(&[0u8; 33]), None);
        assert_eq!(payload_hash_from_group_id(&[1u8; 10]), None);
    }
}
