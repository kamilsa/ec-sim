//! Payload-propagation simulator — Shadow-compatible entry point.
//!
//! Connections warm up, the builder publishes a single payload, every node
//! observes for a window, then exits. Hybrid runs additionally select nodes
//! that receive RS shards and bridge reconstructed payloads back to gossipsub.

#[macro_use]
mod events;
mod coding;
mod network;
mod gossipsub_chunks;
mod payload_chunks;
mod rlnc;
mod rlnc_proto;

use crate::coding::{
    decode_payload_with, encode_payload_shards, encode_payload_shards_with, ColumnShardMessage,
    RsParams, PAYLOAD_DATA_SHARDS, PAYLOAD_TOTAL_SHARDS,
};
use crate::events::hex_bytes;
use crate::network::{
    build_swarm, chunk_subnet_from_topic, chunk_subnet_topic, column_from_topic, column_topic,
    content_message_id_for, dial_peers, gossip_byte_totals, keypair_from_seed,
    mesh_peer_count, payload_chunk_topic, payload_chunked_topic, payload_rs_topic, payload_topic,
    subscribe_partial, GossipTuning, MeshTuning,
    SimBehaviour, SimBehaviourEvent, MAX_CHUNK_SUBNETS, NUM_COLUMNS,
};
use crate::gossipsub_chunks::{split_payload, GossipsubChunkAssembler, GossipsubChunkMessage};
use crate::payload_chunks::{
    assign_chunk_recipients, payload_hash_from_group_id, CellBitmap, OutgoingPayloadChunks,
    PartialPayloadChunks, PayloadChunkAssembler, PayloadChunkHeader, PayloadChunkHeaderTracker,
};
use crate::rlnc::{encode_source, recode, verify_packet, Decoder, Packet, WirePacket};
use crate::rlnc_proto::RlncAck;
use clap::{Parser, ValueEnum};
use futures::StreamExt;
use libp2p::{gossipsub, request_response, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};
use std::sync::Arc;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::time::{self, Duration, Instant};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Propagation protocol selected for this node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Mode {
    #[default]
    Gossipsub,
    #[value(name = "gossipsub-chunked")]
    GossipsubChunked,
    #[value(name = "rs-partial")]
    RsPartial,
    #[value(name = "rs-subnets")]
    RsSubnets,
    #[value(name = "chunk-subnets")]
    ChunkSubnets,
    #[value(name = "gossipsub-rs")]
    GossipsubRs,
    Hybrid,
    Rlnc,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mode::Gossipsub => "gossipsub",
            Mode::GossipsubChunked => "gossipsub-chunked",
            Mode::RsPartial => "rs-partial",
            Mode::RsSubnets => "rs-subnets",
            Mode::ChunkSubnets => "chunk-subnets",
            Mode::GossipsubRs => "gossipsub-rs",
            Mode::Hybrid => "hybrid",
            Mode::Rlnc => "rlnc",
        })
    }
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    let parsed: usize = value
        .parse()
        .map_err(|_| format!("{value:?} is not a positive integer"))?;
    if parsed == 0 {
        return Err("must be a positive integer".to_string());
    }
    Ok(parsed)
}

/// Shadow-compatible payload-propagation simulator.
#[derive(Parser, Debug)]
#[command(name = "ec-sim", version, about)]
struct Cli {
    /// Propagation mode for this node.
    #[arg(long, value_enum, default_value_t = Mode::Gossipsub)]
    mode: Mode,

    /// This node is the builder (publishes the payload once after warmup).
    #[arg(long, default_value_t = false)]
    builder: bool,

    /// Subscribe to all RS column subnets in hybrid mode.
    #[arg(long, default_value_t = false)]
    rs_subnet_subscriber: bool,

    /// Deterministic RNG seed (launcher sets sim.seed + node index).
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// QUIC listen port.
    #[arg(long, default_value_t = 9000)]
    listen_port: u16,

    /// Print one libp2p PeerId per seed (via `keypair_from_seed`) and exit.
    /// Used by the launcher so Python never re-encodes PeerIds.
    #[arg(long, value_delimiter = ',')]
    dump_peer_ids: Vec<u64>,

    /// Bootstrap peer multiaddrs to dial (QUIC).
    #[arg(long = "peer")]
    peers: Vec<Multiaddr>,

    /// Path to a PeerId-keyed `peers.json`.
    #[arg(long)]
    peer_list: Option<PathBuf>,

    /// Payload size in KiB.
    #[arg(long, default_value_t = 256)]
    payload_size_kib: usize,

    /// Extra wait after connections (and mesh, for gossipsub modes) are ready.
    #[arg(long, default_value_t = 15)]
    warmup_secs: u64,

    /// How long to stay up after the builder publishes.
    #[arg(long, default_value_t = 20)]
    observe_secs: u64,

    /// Shards seeded per mesh peer in `rs-partial` mode.
    #[arg(long, default_value_t = 4)]
    payload_chunk_recipients: usize,

    /// Number of raw chunks published in `gossipsub-chunked` mode.
    #[arg(long, default_value_t = 64, value_parser = parse_positive_usize)]
    gossipsub_chunk_count: usize,

    /// Send IDONTWANT to chunk-topic mesh peers after accepting each chunk.
    #[arg(long, default_value_t = false)]
    chunked_send_idontwant: bool,

    /// Lazy-gossip peer floor (`D_lazy`) in `gossipsub-chunked` mode.
    #[arg(long, default_value_t = 0)]
    chunked_gossip_lazy: usize,

    /// RLNC source-packet count `N`.
    #[arg(long, default_value_t = 10)]
    rlnc_chunks: usize,

    /// RLNC push fanout `D`.
    #[arg(long, default_value_t = 40)]
    rlnc_fanout: usize,

    /// Publish to every subscribed peer instead of `mesh_n` of them.
    #[arg(long, default_value_t = false)]
    flood_publish: bool,

    /// Floor for the lazy-gossip peer count (`D_lazy`).
    #[arg(long, default_value_t = 0)]
    gossip_lazy: usize,

    /// Fraction of non-mesh peers to gossip to.
    #[arg(long, default_value_t = 0.0)]
    gossip_factor: f64,

    /// Execution payload mesh target size (`D`).
    #[arg(long, default_value_t = 8)]
    execution_mesh_n: usize,

    /// Execution payload mesh low-water mark (`D_low`).
    #[arg(long, default_value_t = 6)]
    execution_mesh_n_low: usize,

    /// Execution payload mesh high-water mark (`D_high`).
    #[arg(long, default_value_t = 12)]
    execution_mesh_n_high: usize,

    /// Execution payload mesh minimum outbound peers (`D_out`).
    #[arg(long, default_value_t = 2)]
    execution_mesh_outbound_min: usize,

    /// Raw chunked payload mesh target size (`D`).
    #[arg(long, default_value_t = 8)]
    chunked_mesh_n: usize,

    /// Raw chunked payload mesh low-water mark (`D_low`).
    #[arg(long, default_value_t = 6)]
    chunked_mesh_n_low: usize,

    /// Raw chunked payload mesh high-water mark (`D_high`).
    #[arg(long, default_value_t = 12)]
    chunked_mesh_n_high: usize,

    /// Raw chunked payload mesh minimum outbound peers (`D_out`).
    #[arg(long, default_value_t = 2)]
    chunked_mesh_outbound_min: usize,

    /// Column subnet mesh target size (`D`).
    #[arg(long, default_value_t = 8)]
    subnet_mesh_n: usize,

    /// Column subnet mesh low-water mark (`D_low`).
    #[arg(long, default_value_t = 6)]
    subnet_mesh_n_low: usize,

    /// Column subnet mesh high-water mark (`D_high`).
    #[arg(long, default_value_t = 12)]
    subnet_mesh_n_high: usize,

    /// Column subnet mesh minimum outbound peers (`D_out`).
    #[arg(long, default_value_t = 2)]
    subnet_mesh_outbound_min: usize,

    /// Partial-message mesh target size (`D`).
    #[arg(long, default_value_t = 8)]
    partial_mesh_n: usize,

    /// Partial-message mesh low-water mark (`D_low`).
    #[arg(long, default_value_t = 6)]
    partial_mesh_n_low: usize,

    /// Partial-message mesh high-water mark (`D_high`).
    #[arg(long, default_value_t = 12)]
    partial_mesh_n_high: usize,

    /// Partial-message mesh minimum outbound peers (`D_out`).
    #[arg(long, default_value_t = 2)]
    partial_mesh_outbound_min: usize,

    /// Raw chunk subnet mesh target size (`D`).
    #[arg(long, default_value_t = 8)]
    chunk_subnet_mesh_n: usize,

    /// Raw chunk subnet mesh low-water mark (`D_low`).
    #[arg(long, default_value_t = 6)]
    chunk_subnet_mesh_n_low: usize,

    /// Raw chunk subnet mesh high-water mark (`D_high`).
    #[arg(long, default_value_t = 12)]
    chunk_subnet_mesh_n_high: usize,

    /// Raw chunk subnet mesh minimum outbound peers (`D_out`).
    #[arg(long, default_value_t = 2)]
    chunk_subnet_mesh_outbound_min: usize,

    /// Single-topic RS shard mesh target size (`D`).
    #[arg(long, default_value_t = 8)]
    gossipsub_rs_mesh_n: usize,

    /// Single-topic RS shard mesh low-water mark (`D_low`).
    #[arg(long, default_value_t = 6)]
    gossipsub_rs_mesh_n_low: usize,

    /// Single-topic RS shard mesh high-water mark (`D_high`).
    #[arg(long, default_value_t = 12)]
    gossipsub_rs_mesh_n_high: usize,

    /// Single-topic RS shard mesh minimum outbound peers (`D_out`).
    #[arg(long, default_value_t = 2)]
    gossipsub_rs_mesh_outbound_min: usize,

    /// `gossipsub-rs`: systematic shards a payload is split into.
    #[arg(long, default_value_t = PAYLOAD_DATA_SHARDS, value_parser = parse_positive_usize)]
    gossipsub_rs_data_shards: usize,

    /// `gossipsub-rs`: total shards after Reed-Solomon extension.
    #[arg(long, default_value_t = PAYLOAD_TOTAL_SHARDS, value_parser = parse_positive_usize)]
    gossipsub_rs_total_shards: usize,
}

#[derive(Debug, Deserialize)]
struct PeerListFile {
    peers: Vec<PeerEntry>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PeerEntry {
    name: String,
    peer_id: String,
    addr: String,
}

fn gossip_tuning(cli: &Cli) -> GossipTuning {
    GossipTuning {
        flood_publish: cli.flood_publish,
        gossip_lazy: if cli.mode == Mode::GossipsubChunked {
            cli.chunked_gossip_lazy
        } else {
            cli.gossip_lazy
        },
        gossip_factor: cli.gossip_factor,
        execution: MeshTuning {
            mesh_n: cli.execution_mesh_n,
            mesh_n_low: cli.execution_mesh_n_low,
            mesh_n_high: cli.execution_mesh_n_high,
            mesh_outbound_min: cli.execution_mesh_outbound_min,
        },
        subnet: MeshTuning {
            mesh_n: cli.subnet_mesh_n,
            mesh_n_low: cli.subnet_mesh_n_low,
            mesh_n_high: cli.subnet_mesh_n_high,
            mesh_outbound_min: cli.subnet_mesh_outbound_min,
        },
        partial: MeshTuning {
            mesh_n: cli.partial_mesh_n,
            mesh_n_low: cli.partial_mesh_n_low,
            mesh_n_high: cli.partial_mesh_n_high,
            mesh_outbound_min: cli.partial_mesh_outbound_min,
        },
        chunked: MeshTuning {
            mesh_n: cli.chunked_mesh_n,
            mesh_n_low: cli.chunked_mesh_n_low,
            mesh_n_high: cli.chunked_mesh_n_high,
            mesh_outbound_min: cli.chunked_mesh_outbound_min,
        },
        chunk_subnet: MeshTuning {
            mesh_n: cli.chunk_subnet_mesh_n,
            mesh_n_low: cli.chunk_subnet_mesh_n_low,
            mesh_n_high: cli.chunk_subnet_mesh_n_high,
            mesh_outbound_min: cli.chunk_subnet_mesh_outbound_min,
        },
        gossipsub_rs: MeshTuning {
            mesh_n: cli.gossipsub_rs_mesh_n,
            mesh_n_low: cli.gossipsub_rs_mesh_n_low,
            mesh_n_high: cli.gossipsub_rs_mesh_n_high,
            mesh_outbound_min: cli.gossipsub_rs_mesh_outbound_min,
        },
        // Only chunk-subnets runs configure these topics; other modes would pay
        // for per-topic mesh entries they never subscribe to.
        chunk_subnet_count: if cli.mode == Mode::ChunkSubnets {
            cli.gossipsub_chunk_count
        } else {
            0
        },
    }
}

/// Reed-Solomon rate for `gossipsub-rs`. Validated once at startup, so the
/// unchecked construction here cannot produce an invalid rate at runtime.
fn gossipsub_rs_params(cli: &Cli) -> RsParams {
    RsParams {
        data: cli.gossipsub_rs_data_shards,
        total: cli.gossipsub_rs_total_shards,
    }
}

fn payload_hash(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    hex_bytes(&digest)
}

fn make_payload(seed: u64, size: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut payload = vec![0u8; size];
    rng.fill_bytes(&mut payload);
    payload
}

fn load_peer_list(path: &PathBuf) -> Result<PeerListFile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn mesh_topic(mode: Mode) -> libp2p::gossipsub::IdentTopic {
    match mode {
        Mode::RsPartial => payload_chunk_topic(),
        Mode::GossipsubChunked => payload_chunked_topic(),
        Mode::RsSubnets => column_topic(0),
        Mode::ChunkSubnets => chunk_subnet_topic(0),
        Mode::GossipsubRs => payload_rs_topic(),
        Mode::Hybrid => payload_topic(),
        _ => payload_topic(),
    }
}

fn chunk_subscriber(mode: Mode, rs_subnet_subscriber: bool) -> bool {
    mode == Mode::RsSubnets || (mode == Mode::Hybrid && rs_subnet_subscriber)
}

fn primary_mesh_tuning(mode: Mode, tuning: &GossipTuning) -> MeshTuning {
    match mode {
        Mode::RsPartial => tuning.partial,
        Mode::RsSubnets => tuning.subnet,
        Mode::ChunkSubnets => tuning.chunk_subnet,
        Mode::GossipsubRs => tuning.gossipsub_rs,
        Mode::GossipsubChunked => tuning.chunked,
        _ => tuning.execution,
    }
}

fn warmup_ready(swarm: &Swarm<SimBehaviour>, cli: &Cli, tuning: &GossipTuning) -> bool {
    let dial_count = cli.peers.len();
    if dial_count == 0 {
        return true;
    }
    let connected = swarm.connected_peers().count();
    let primary_mesh = primary_mesh_tuning(cli.mode, tuning);
    let conn_ok = connected >= dial_count.min(primary_mesh.mesh_n.max(1));
    if cli.mode == Mode::Rlnc {
        return conn_ok;
    }
    let mesh = mesh_peer_count(swarm, &mesh_topic(cli.mode));
    let mesh_ok = mesh >= primary_mesh.mesh_n_low.min(connected.max(1));
    let subnet_mesh_ok = !(cli.mode == Mode::Hybrid
        && cli.builder
        && chunk_subscriber(cli.mode, cli.rs_subnet_subscriber))
        || mesh_peer_count(swarm, &column_topic(0)) >= 1;
    conn_ok && mesh_ok && subnet_mesh_ok
}

fn mark_reconstructed(reconstructed: &mut bool, payload: &[u8]) {
    if *reconstructed {
        return;
    }
    *reconstructed = true;
    let hash = payload_hash(payload);
    event!(
        "payload_received",
        bytes = payload.len(),
        hash = hash
    );
    event!(
        "payload_reconstructed",
        bytes = payload.len(),
        hash = hash
    );
}

fn gossipsub_publish_payload(swarm: &mut Swarm<SimBehaviour>, payload: &[u8]) -> bool {
    match swarm
        .behaviour_mut()
        .gossipsub
        .publish(payload_topic(), payload.to_vec())
    {
        Ok(_) => true,
        Err(err) => {
            warn!(%err, "gossipsub publish failed");
            false
        }
    }
}

fn publish_gossipsub(swarm: &mut Swarm<SimBehaviour>, payload: &[u8]) {
    if gossipsub_publish_payload(swarm, payload) {
        event!(
            "payload_published",
            bytes = payload.len(),
            hash = payload_hash(payload)
        );
    }
}

fn publish_gossipsub_chunked(
    swarm: &mut Swarm<SimBehaviour>,
    payload: &[u8],
    chunk_count: usize,
) {
    let chunks = match split_payload(payload, chunk_count) {
        Ok(chunks) => chunks,
        Err(err) => {
            warn!(%err, "gossipsub chunk split failed");
            return;
        }
    };
    let total = chunks.len();
    let mut published = 0usize;
    for chunk in chunks {
        match swarm
            .behaviour_mut()
            .gossipsub
            .publish(payload_chunked_topic(), chunk.encode())
        {
            Ok(_) => published += 1,
            Err(err) => warn!(%err, "gossipsub chunk publish failed"),
        }
    }
    if published == total {
        event!(
            "payload_published",
            bytes = payload.len(),
            hash = payload_hash(payload),
            chunks = total
        );
    } else {
        warn!(published, total, "not all gossipsub chunks were published");
    }
}

fn handle_gossipsub_chunked(
    swarm: &mut Swarm<SimBehaviour>,
    state: &mut GossipsubChunkAssembler,
    reconstructed: &mut bool,
    idontwant_message_id: Option<gossipsub::MessageId>,
    data: &[u8],
) {
    let Ok(chunk) = GossipsubChunkMessage::decode(data) else {
        return;
    };
    let chunk_count = chunk.chunk_count;
    let outcome = state.merge(chunk);
    if outcome.added {
        event!(
            "chunk_received",
            added = 1,
            distinct = outcome.distinct,
            chunks = chunk_count
        );
        if let Some(message_id) = idontwant_message_id {
            let peers = swarm
                .behaviour_mut()
                .gossipsub
                .send_idontwant_to_mesh(payload_chunked_topic().hash(), [message_id]);
            event!("chunk_idontwant_sent", peers = peers);
        }
    }
    if let Some(payload) = outcome.payload {
        mark_reconstructed(reconstructed, &payload);
    }
}

/// Publish each raw chunk on its own subnet topic (mode `chunk-subnets`).
///
/// Unlike `rs-subnets` there is no erasure coding: every chunk is required, so a
/// receiver reconstructs only once all of them arrive.
fn publish_chunk_subnets(swarm: &mut Swarm<SimBehaviour>, payload: &[u8], chunk_count: usize) {
    let chunks = match split_payload(payload, chunk_count) {
        Ok(chunks) => chunks,
        Err(err) => {
            warn!(%err, "chunk-subnets split failed");
            return;
        }
    };
    let total = chunks.len();
    let mut published = 0usize;
    for (index, chunk) in chunks.into_iter().enumerate() {
        match swarm
            .behaviour_mut()
            .gossipsub
            .publish(chunk_subnet_topic(index), chunk.encode())
        {
            Ok(_) => published += 1,
            Err(err) => warn!(subnet = index, %err, "chunk-subnets publish failed"),
        }
    }
    if published == total {
        event!(
            "payload_published",
            bytes = payload.len(),
            hash = payload_hash(payload),
            chunks = total
        );
    } else {
        warn!(published, total, "not all chunk subnets were published");
    }
}

fn handle_chunk_subnets(
    swarm: &mut Swarm<SimBehaviour>,
    state: &mut GossipsubChunkAssembler,
    reconstructed: &mut bool,
    idontwant_message_id: Option<gossipsub::MessageId>,
    topic: &str,
    data: &[u8],
) {
    let Some(subnet) = chunk_subnet_from_topic(topic) else {
        return;
    };
    let Ok(chunk) = GossipsubChunkMessage::decode(data) else {
        return;
    };
    // A chunk only counts on the subnet that carries its index, so a misrouted
    // or mislabelled message cannot be merged.
    if chunk.index as usize != subnet {
        return;
    }
    let chunk_count = chunk.chunk_count;
    let outcome = state.merge(chunk);
    if outcome.added {
        event!(
            "chunk_received",
            subnet = subnet,
            added = 1,
            distinct = outcome.distinct,
            chunks = chunk_count
        );
        if let Some(message_id) = idontwant_message_id {
            let peers = swarm
                .behaviour_mut()
                .gossipsub
                .send_idontwant_to_mesh(chunk_subnet_topic(subnet).hash(), [message_id]);
            event!("chunk_idontwant_sent", subnet = subnet, peers = peers);
        }
    }
    if let Some(payload) = outcome.payload {
        mark_reconstructed(reconstructed, &payload);
    }
}

struct RsPartialState {
    assembler: PayloadChunkAssembler,
    header_tracker: PayloadChunkHeaderTracker,
    recipients: usize,
}

fn publish_rs_partial(
    swarm: &mut Swarm<SimBehaviour>,
    state: &mut RsPartialState,
    payload: &[u8],
    reconstructed: &mut bool,
) {
    let (shard_len, payload_hash, shards) = match encode_payload_shards(payload) {
        Ok(encoded) => encoded,
        Err(err) => {
            warn!(%err, "rs-partial encode failed");
            return;
        }
    };
    let header = PayloadChunkHeader::new(payload.len(), shard_len, payload_hash);
    let mut bitmap = CellBitmap::with_len(PAYLOAD_TOTAL_SHARDS);
    for idx in 0..PAYLOAD_TOTAL_SHARDS {
        bitmap.set(idx);
    }
    let full = PartialPayloadChunks {
        shards_present_bitmap: bitmap,
        shards,
        header: None,
    };
    state.assembler.set_header(payload_hash, header.clone());
    let outcome = state.assembler.merge_partial(payload_hash, &full);
    if outcome.crossed_threshold {
        if let Some(generation) = state.assembler.generation(&payload_hash) {
            let _ = state.assembler.reconstruct(payload_hash, generation);
        }
    }

    let topic = payload_chunk_topic();
    let mesh_peers: Vec<PeerId> = swarm
        .behaviour()
        .gossipsub
        .mesh_peers(&topic.hash())
        .copied()
        .collect();
    let assignment = assign_chunk_recipients(&payload_hash, &mesh_peers, state.recipients);
    let header_sent = state.header_tracker.get_for_payload(payload_hash);
    let outgoing = OutgoingPayloadChunks::new(
        Arc::new(full),
        &header,
        header_sent,
        CellBitmap::all_set(PAYLOAD_TOTAL_SHARDS),
        Some(Arc::new(assignment)),
    );
    match swarm
        .behaviour_mut()
        .gossipsub
        .publish_partial(topic.hash(), outgoing)
    {
        Ok(_) => {
            event!(
                "payload_published",
                bytes = payload.len(),
                hash = hex_bytes(&payload_hash),
                shards = PAYLOAD_TOTAL_SHARDS,
                shard_len = shard_len,
                mesh_peers = mesh_peers.len()
            );
            mark_reconstructed(reconstructed, payload);
        }
        Err(err) => warn!(%err, "rs-partial publish failed"),
    }
}

fn republish_rs_partial(swarm: &mut Swarm<SimBehaviour>, state: &mut RsPartialState, hash: [u8; 32]) {
    let Some(header) = state.assembler.get_header(&hash) else {
        return;
    };
    let Some(current) = state.assembler.current_partial(&hash) else {
        return;
    };
    let header_sent = state.header_tracker.get_for_payload(hash);
    let outgoing = OutgoingPayloadChunks::new(
        Arc::new(current),
        &header,
        header_sent,
        CellBitmap::all_set(PAYLOAD_TOTAL_SHARDS),
        None,
    );
    let _ = swarm
        .behaviour_mut()
        .gossipsub
        .publish_partial(payload_chunk_topic().hash(), outgoing);
}

fn handle_rs_partial(
    swarm: &mut Swarm<SimBehaviour>,
    state: &mut RsPartialState,
    reconstructed: &mut bool,
    group_id: &[u8],
    message: Option<Vec<u8>>,
) {
    let Some(payload_hash) = payload_hash_from_group_id(group_id) else {
        return;
    };
    let Some(bytes) = message else {
        return;
    };
    let Ok(chunks) = PartialPayloadChunks::decode(&bytes) else {
        return;
    };
    if !chunks.is_structurally_valid() {
        return;
    }
    let outcome = state.assembler.merge_partial(payload_hash, &chunks);
    if outcome.added_shards > 0 {
        event!(
            "shard_received",
            added = outcome.added_shards,
            distinct = outcome.distinct_shards
        );
    }
    if outcome.added_shards > 0 || outcome.learned_header {
        // A header-only first contact must advertise its missing shards so the
        // relay can answer the partial-message protocol's request handshake.
        republish_rs_partial(swarm, state, payload_hash);
    }
    if outcome.crossed_threshold {
        if let Some(generation) = state.assembler.generation(&payload_hash) {
            if let Some(payload) = state.assembler.reconstruct(payload_hash, generation) {
                mark_reconstructed(reconstructed, &payload);
                republish_rs_partial(swarm, state, payload_hash);
            }
        }
    }
}

/// Collected RS shards for one payload.
///
/// Shared by `rs-subnets` / `hybrid` (one topic per shard, always the default
/// 64-of-128 rate) and `gossipsub-rs` (all shards on one topic, configurable
/// rate). Only the shard *index source* and the IDONTWANT topic layout differ.
struct RsSubnetState {
    params: RsParams,
    shards: Vec<Option<Vec<u8>>>,
    payload_len: Option<usize>,
    shard_len: Option<usize>,
    payload_hash: Option<[u8; 32]>,
    bridge_payload: bool,
    chunks_reconstructed: bool,
}

impl RsSubnetState {
    fn new(bridge_payload: bool) -> Self {
        Self::with_params(RsParams::DEFAULT, bridge_payload)
    }

    fn with_params(params: RsParams, bridge_payload: bool) -> Self {
        Self {
            params,
            shards: vec![None; params.total],
            payload_len: None,
            shard_len: None,
            payload_hash: None,
            bridge_payload,
            chunks_reconstructed: false,
        }
    }

    fn distinct(&self) -> usize {
        self.shards.iter().filter(|s| s.is_some()).count()
    }
}

/// Where the shards of a payload live, which decides how a reconstructing node
/// addresses its IDONTWANT notifications.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ShardTopics {
    /// One topic per shard index (`rs-subnets`, `hybrid`).
    PerColumn,
    /// Every shard on a single topic (`gossipsub-rs`).
    Single,
}

impl ShardTopics {
    fn topic_for(&self, index: usize) -> gossipsub::TopicHash {
        match self {
            Self::PerColumn => column_topic(index).hash(),
            Self::Single => payload_rs_topic().hash(),
        }
    }
}

fn publish_rs_subnet_shards(
    swarm: &mut Swarm<SimBehaviour>,
    payload: &[u8],
) -> Option<(usize, usize, [u8; 32])> {
    let (shard_len, payload_hash, shards) = match encode_payload_shards(payload) {
        Ok(encoded) => encoded,
        Err(err) => {
            warn!(%err, "rs-subnets encode failed");
            return None;
        }
    };
    let mut published = 0usize;
    for (i, data) in shards.into_iter().enumerate() {
        let msg = ColumnShardMessage {
            index: i as u16,
            payload_len: payload.len() as u64,
            shard_len: shard_len as u64,
            payload_hash,
            data,
        };
        match swarm
            .behaviour_mut()
            .gossipsub
            .publish(column_topic(i), msg.encode())
        {
            Ok(_) => published += 1,
            Err(err) => warn!(column = i, %err, "rs-subnets column publish failed"),
        }
    }
    Some((published, shard_len, payload_hash))
}

fn publish_rs_subnets(swarm: &mut Swarm<SimBehaviour>, payload: &[u8], reconstructed: &mut bool) {
    let Some((published, shard_len, payload_hash)) = publish_rs_subnet_shards(swarm, payload)
    else {
        return;
    };
    event!(
        "payload_published",
        bytes = payload.len(),
        hash = hex_bytes(&payload_hash),
        shards = published,
        shard_len = shard_len
    );
    mark_reconstructed(reconstructed, payload);
}

fn publish_hybrid(swarm: &mut Swarm<SimBehaviour>, payload: &[u8], reconstructed: &mut bool) {
    let full_payload_published = gossipsub_publish_payload(swarm, payload);
    let (shards, shard_len, hash) = publish_rs_subnet_shards(swarm, payload)
        .map(|(shards, shard_len, hash)| (shards, shard_len, hex_bytes(&hash)))
        .unwrap_or((0, 0, payload_hash(payload)));
    if full_payload_published || shards > 0 {
        event!(
            "payload_published",
            bytes = payload.len(),
            hash = hash,
            full_payload = full_payload_published,
            shards = shards,
            shard_len = shard_len
        );
    }
    mark_reconstructed(reconstructed, payload);
}

/// Tell mesh peers to stop sending shards this node can now derive itself.
///
/// A reconstructing node regenerates the full shard set, so it can suppress
/// shards it never actually received. Per-column layouts need one call per
/// topic; a single-topic layout sends every id in one IDONTWANT per mesh peer.
fn send_reconstructed_chunk_idontwants(
    swarm: &mut Swarm<SimBehaviour>,
    layout: ShardTopics,
    payload_len: usize,
    shard_len: usize,
    payload_hash: [u8; 32],
    shards: &[Vec<u8>],
) -> usize {
    let mut batches: Vec<(gossipsub::TopicHash, Vec<gossipsub::MessageId>)> = Vec::new();
    for (index, data) in shards.iter().enumerate() {
        let topic = layout.topic_for(index);
        let message = ColumnShardMessage {
            index: index as u16,
            payload_len: payload_len as u64,
            shard_len: shard_len as u64,
            payload_hash,
            data: data.clone(),
        };
        let message_id = content_message_id_for(&topic, &message.encode());
        match batches.last_mut() {
            Some((last, ids)) if *last == topic => ids.push(message_id),
            _ => batches.push((topic, vec![message_id])),
        }
    }
    let mut peers = 0;
    for (topic, ids) in batches {
        peers += swarm
            .behaviour_mut()
            .gossipsub
            .send_idontwant_to_mesh(topic, ids);
    }
    peers
}

/// Merge one shard. Returns the distinct-shard count when the shard was new,
/// or `None` for a duplicate, an out-of-range index, or a shard whose declared
/// index disagrees with where it arrived.
fn merge_rs_shard(
    state: &mut RsSubnetState,
    index: usize,
    msg: ColumnShardMessage,
) -> Option<usize> {
    if index >= state.params.total || msg.index as usize != index {
        return None;
    }
    if state.shards[index].is_some() {
        return None;
    }
    state.shards[index] = Some(msg.data);
    state.payload_len = Some(msg.payload_len as usize);
    state.shard_len = Some(msg.shard_len as usize);
    state.payload_hash = Some(msg.payload_hash);
    Some(state.distinct())
}

/// Decode once enough distinct shards are held, then suppress the rest.
fn try_reconstruct_rs(
    swarm: &mut Swarm<SimBehaviour>,
    state: &mut RsSubnetState,
    reconstructed: &mut bool,
    layout: ShardTopics,
    distinct: usize,
) {
    if state.chunks_reconstructed || distinct < state.params.data {
        return;
    }
    let (Some(payload_len), Some(shard_len), Some(hash)) =
        (state.payload_len, state.shard_len, state.payload_hash)
    else {
        return;
    };
    let present: Vec<(usize, Vec<u8>)> = state
        .shards
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.clone().map(|d| (i, d)))
        .collect();
    match decode_payload_with(payload_len, shard_len, &hash, &present, state.params) {
        Ok((payload, full_shards)) => {
            state.chunks_reconstructed = true;
            let idontwant_peers = send_reconstructed_chunk_idontwants(
                swarm,
                layout,
                payload_len,
                shard_len,
                hash,
                &full_shards,
            );
            event!(
                "reconstructed_chunk_idontwant_sent",
                chunks = full_shards.len(),
                peers = idontwant_peers
            );
            mark_reconstructed(reconstructed, &payload);
            if state.bridge_payload && gossipsub_publish_payload(swarm, &payload) {
                event!(
                    "payload_bridged",
                    bytes = payload.len(),
                    hash = payload_hash(&payload)
                );
            }
        }
        Err(err) => warn!(%err, "rs reconstruct failed"),
    }
}

fn handle_rs_subnets(
    swarm: &mut Swarm<SimBehaviour>,
    state: &mut RsSubnetState,
    reconstructed: &mut bool,
    topic: &str,
    data: &[u8],
) {
    let Some(column) = column_from_topic(topic) else {
        return;
    };
    let Ok(msg) = ColumnShardMessage::decode(data) else {
        return;
    };
    let Some(distinct) = merge_rs_shard(state, column, msg) else {
        return;
    };
    event!(
        "shard_received",
        column = column,
        added = 1,
        distinct = distinct
    );
    try_reconstruct_rs(
        swarm,
        state,
        reconstructed,
        ShardTopics::PerColumn,
        distinct,
    );
}

/// Publish every RS shard as an ordinary Gossipsub message on one topic
/// (mode `gossipsub-rs`).
fn publish_gossipsub_rs(
    swarm: &mut Swarm<SimBehaviour>,
    payload: &[u8],
    params: RsParams,
    reconstructed: &mut bool,
) {
    let (shard_len, payload_hash, shards) = match encode_payload_shards_with(payload, params) {
        Ok(encoded) => encoded,
        Err(err) => {
            warn!(%err, "gossipsub-rs encode failed");
            return;
        }
    };
    let mut published = 0usize;
    for (index, data) in shards.into_iter().enumerate() {
        let msg = ColumnShardMessage {
            index: index as u16,
            payload_len: payload.len() as u64,
            shard_len: shard_len as u64,
            payload_hash,
            data,
        };
        match swarm
            .behaviour_mut()
            .gossipsub
            .publish(payload_rs_topic(), msg.encode())
        {
            Ok(_) => published += 1,
            Err(err) => warn!(shard = index, %err, "gossipsub-rs publish failed"),
        }
    }
    event!(
        "payload_published",
        bytes = payload.len(),
        hash = hex_bytes(&payload_hash),
        shards = published,
        shard_len = shard_len,
        data_shards = params.data,
        total_shards = params.total
    );
    mark_reconstructed(reconstructed, payload);
}

fn handle_gossipsub_rs(
    swarm: &mut Swarm<SimBehaviour>,
    state: &mut RsSubnetState,
    reconstructed: &mut bool,
    idontwant_message_id: Option<gossipsub::MessageId>,
    data: &[u8],
) {
    let Ok(msg) = ColumnShardMessage::decode(data) else {
        return;
    };
    // A single topic carries every shard, so the index comes from the message.
    let index = msg.index as usize;
    let Some(distinct) = merge_rs_shard(state, index, msg) else {
        return;
    };
    event!(
        "shard_received",
        index = index,
        added = 1,
        distinct = distinct
    );
    if let Some(message_id) = idontwant_message_id {
        let peers = swarm
            .behaviour_mut()
            .gossipsub
            .send_idontwant_to_mesh(payload_rs_topic().hash(), [message_id]);
        event!("shard_idontwant_sent", index = index, peers = peers);
    }
    try_reconstruct_rs(swarm, state, reconstructed, ShardTopics::Single, distinct);
}

/// Gossipsub topic hashes the event loop dispatches on.
struct TopicHashes {
    payload: gossipsub::TopicHash,
    chunk: gossipsub::TopicHash,
    chunked: gossipsub::TopicHash,
    rs: gossipsub::TopicHash,
}

impl TopicHashes {
    fn new() -> Self {
        Self {
            payload: payload_topic().hash(),
            chunk: payload_chunk_topic().hash(),
            chunked: payload_chunked_topic().hash(),
            rs: payload_rs_topic().hash(),
        }
    }
}

/// Per-mode receive state. Exactly one variant is live for a run, so the mode
/// that owns an incoming message is decided by the type rather than by which of
/// several `Option`s happens to be populated.
enum ModeState {
    /// Modes that reconstruct directly from a full payload message.
    FullPayload,
    Chunked(GossipsubChunkAssembler),
    ChunkSubnets(GossipsubChunkAssembler),
    RsPartial(RsPartialState),
    /// `rs-subnets`, plus `hybrid` nodes holding the chunk-subscriber role.
    RsSubnets(RsSubnetState),
    /// Every RS shard arriving on one topic.
    GossipsubRs(RsSubnetState),
    /// Boxed: `RlncState` embeds an RNG and dwarfs the other variants.
    Rlnc(Box<RlncState>),
}

fn build_mode_state(cli: &Cli) -> ModeState {
    match cli.mode {
        Mode::RsPartial => ModeState::RsPartial(RsPartialState {
            assembler: PayloadChunkAssembler::new(4),
            header_tracker: PayloadChunkHeaderTracker::new(4),
            recipients: cli.payload_chunk_recipients,
        }),
        Mode::GossipsubChunked => ModeState::Chunked(GossipsubChunkAssembler::new()),
        Mode::ChunkSubnets => ModeState::ChunkSubnets(GossipsubChunkAssembler::new()),
        Mode::GossipsubRs => ModeState::GossipsubRs(RsSubnetState::with_params(
            gossipsub_rs_params(cli),
            false,
        )),
        Mode::Rlnc => ModeState::Rlnc(Box::new(RlncState::new(
            cli.rlnc_chunks,
            cli.rlnc_fanout,
            cli.seed,
        ))),
        // Covers rs-subnets and the hybrid chunk-subscriber role; a hybrid node
        // without that role only ever sees full payload gossip.
        _ if chunk_subscriber(cli.mode, cli.rs_subnet_subscriber) => {
            ModeState::RsSubnets(RsSubnetState::new(cli.mode == Mode::Hybrid))
        }
        _ => ModeState::FullPayload,
    }
}

/// Publish the payload once, in whichever shape this run's mode calls for.
fn publish_payload(
    swarm: &mut Swarm<SimBehaviour>,
    cli: &Cli,
    payload: &[u8],
    reconstructed: &mut bool,
    state: &mut ModeState,
) {
    match cli.mode {
        Mode::RsPartial => {
            if let ModeState::RsPartial(rs) = state {
                publish_rs_partial(swarm, rs, payload, reconstructed);
            }
        }
        Mode::GossipsubChunked => {
            publish_gossipsub_chunked(swarm, payload, cli.gossipsub_chunk_count);
            mark_reconstructed(reconstructed, payload);
        }
        Mode::RsSubnets => publish_rs_subnets(swarm, payload, reconstructed),
        Mode::ChunkSubnets => {
            publish_chunk_subnets(swarm, payload, cli.gossipsub_chunk_count);
            mark_reconstructed(reconstructed, payload);
        }
        Mode::GossipsubRs => {
            publish_gossipsub_rs(swarm, payload, gossipsub_rs_params(cli), reconstructed);
        }
        Mode::Hybrid if chunk_subscriber(cli.mode, cli.rs_subnet_subscriber) => {
            publish_hybrid(swarm, payload, reconstructed);
        }
        Mode::Rlnc => {
            if let ModeState::Rlnc(rlnc) = state {
                publish_rlnc(swarm, rlnc, payload, reconstructed, cli.seed);
            }
        }
        Mode::Gossipsub | Mode::Hybrid => {
            publish_gossipsub(swarm, payload);
            mark_reconstructed(reconstructed, payload);
        }
    }
}

fn handle_swarm_event(
    swarm: &mut Swarm<SimBehaviour>,
    event: SwarmEvent<SimBehaviourEvent>,
    reconstructed: &mut bool,
    topics: &TopicHashes,
    chunked_send_idontwant: bool,
    state: &mut ModeState,
) {
    match event {
        SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            message,
            ..
        })) if message.topic == topics.payload => {
            mark_reconstructed(reconstructed, &message.data);
        }
        SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            message_id, message, ..
        })) if message.topic == topics.chunked => {
            if let ModeState::Chunked(chunked) = state {
                handle_gossipsub_chunked(
                    swarm,
                    chunked,
                    reconstructed,
                    chunked_send_idontwant.then_some(message_id),
                    &message.data,
                );
            }
        }
        SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            message_id, message, ..
        })) if message.topic == topics.rs => {
            if let ModeState::GossipsubRs(shards) = state {
                handle_gossipsub_rs(
                    swarm,
                    shards,
                    reconstructed,
                    chunked_send_idontwant.then_some(message_id),
                    &message.data,
                );
            }
        }
        SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            message_id, message, ..
        })) => match state {
            ModeState::ChunkSubnets(chunks) => handle_chunk_subnets(
                swarm,
                chunks,
                reconstructed,
                chunked_send_idontwant.then_some(message_id),
                message.topic.as_str(),
                &message.data,
            ),
            ModeState::RsSubnets(shards) => handle_rs_subnets(
                swarm,
                shards,
                reconstructed,
                message.topic.as_str(),
                &message.data,
            ),
            _ => {}
        },
        SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Partial {
            topic_hash,
            group_id,
            message,
            ..
        })) if topic_hash == topics.chunk => {
            if let ModeState::RsPartial(partial) = state {
                handle_rs_partial(swarm, partial, reconstructed, &group_id, message);
            }
        }
        SwarmEvent::Behaviour(SimBehaviourEvent::Rlnc(request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request,
                    channel,
                    ..
                },
            ..
        })) => {
            let _ = swarm.behaviour_mut().rlnc.send_response(channel, RlncAck);
            if let ModeState::Rlnc(rlnc) = state {
                handle_rlnc_packet(swarm, rlnc, reconstructed, peer, request);
            }
        }
        _ => {}
    }
}

struct RlncState {
    n: usize,
    fanout: usize,
    decoder: Option<Decoder>,
    held: Vec<Packet>,
    sig_ok: bool,
    tx: u64,
    rx: u64,
    rng: StdRng,
}

impl RlncState {
    fn new(n: usize, fanout: usize, seed: u64) -> Self {
        Self {
            n,
            fanout,
            decoder: None,
            held: Vec::new(),
            sig_ok: false,
            tx: 0,
            rx: 0,
            rng: StdRng::seed_from_u64(seed),
        }
    }
}

fn pick_fanout(
    swarm: &Swarm<SimBehaviour>,
    exclude: Option<PeerId>,
    fanout: usize,
    rng: &mut StdRng,
) -> Vec<PeerId> {
    let mut peers: Vec<PeerId> = swarm
        .connected_peers()
        .copied()
        .filter(|p| exclude != Some(*p))
        .collect();
    peers.sort();
    peers.shuffle(rng);
    let take = fanout.min(peers.len());
    peers.truncate(take);
    peers
}

fn rlnc_push(swarm: &mut Swarm<SimBehaviour>, state: &mut RlncState, exclude: Option<PeerId>) {
    if state.held.is_empty() {
        return;
    }
    for peer in pick_fanout(swarm, exclude, state.fanout, &mut state.rng) {
        let Some(coded) = recode(&state.held, &mut state.rng) else {
            continue;
        };
        let wire = coded.to_wire();
        state.tx += wire.encoded_len();
        swarm.behaviour_mut().rlnc.send_request(&peer, wire);
    }
}

fn publish_rlnc(
    swarm: &mut Swarm<SimBehaviour>,
    state: &mut RlncState,
    payload: &[u8],
    reconstructed: &mut bool,
    seed: u64,
) {
    let keypair = keypair_from_seed(seed);
    let source = encode_source(payload, state.n, &keypair);
    if let Some(first) = source.first() {
        state.decoder = Some(Decoder::from_packet(first));
    }
    for packet in &source {
        if let Some(decoder) = state.decoder.as_mut() {
            decoder.insert(packet);
        }
        state.held.push(packet.clone());
    }
    state.sig_ok = true;
    rlnc_push(swarm, state, None);
    event!(
        "payload_published",
        bytes = payload.len(),
        hash = payload_hash(payload),
        n = state.n,
        fanout = state.fanout
    );
    event!("rlnc_packet", rank = state.held.len().min(state.n));
    mark_reconstructed(reconstructed, payload);
}

fn handle_rlnc_packet(
    swarm: &mut Swarm<SimBehaviour>,
    state: &mut RlncState,
    reconstructed: &mut bool,
    from: PeerId,
    wire: WirePacket,
) {
    state.rx += wire.encoded_len();
    let Some(packet) = Packet::from_wire(&wire) else {
        return;
    };
    if !verify_packet(&packet, state.sig_ok) {
        return;
    }
    state.sig_ok = true;
    if state.decoder.is_none() {
        state.decoder = Some(Decoder::from_packet(&packet));
    }
    let Some(decoder) = state.decoder.as_mut() else {
        return;
    };
    if !decoder.insert(&packet) {
        return;
    }
    state.held.push(packet);
    let rank = decoder.rank();
    event!("rlnc_packet", rank = rank);
    if !*reconstructed {
        if let Some(payload) = decoder.decode() {
            mark_reconstructed(reconstructed, &payload);
        }
    }
    rlnc_push(swarm, state, Some(from));
}

fn finish(swarm: &Swarm<SimBehaviour>, reconstructed: bool, state: &ModeState) {
    let (mut tx, mut rx) = gossip_byte_totals(swarm);
    // RLNC rides its own request-response protocol, so its bytes are not in the
    // gossipsub counters.
    if let ModeState::Rlnc(rlnc) = state {
        tx += rlnc.tx;
        rx += rlnc.rx;
    }
    event!("bytes", tx = tx, rx = rx);
    event!("run_end", reconstructed = reconstructed);
}

// A single-threaded runtime: under Shadow every guest thread is simulated on a
// deterministic scheduler, so tokio's multi-threaded work-stealing runtime only
// adds simulated context-switch overhead without any parallelism benefit.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    if !cli.dump_peer_ids.is_empty() {
        for seed in &cli.dump_peer_ids {
            let peer_id = PeerId::from(keypair_from_seed(*seed).public());
            println!("{peer_id}");
        }
        return;
    }

    if !matches!(
        cli.mode,
        Mode::Gossipsub
            | Mode::GossipsubChunked
            | Mode::RsPartial
            | Mode::RsSubnets
            | Mode::ChunkSubnets
            | Mode::GossipsubRs
            | Mode::Hybrid
            | Mode::Rlnc
    ) {
        eprintln!("error: mode {} is not implemented yet", cli.mode);
        std::process::exit(1);
    }

    if cli.mode == Mode::GossipsubRs {
        if let Err(error) = RsParams::new(cli.gossipsub_rs_data_shards, cli.gossipsub_rs_total_shards)
        {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }

    if cli.mode == Mode::ChunkSubnets && cli.gossipsub_chunk_count > MAX_CHUNK_SUBNETS {
        eprintln!(
            "error: chunk-subnets supports at most {MAX_CHUNK_SUBNETS} chunks, got {}",
            cli.gossipsub_chunk_count
        );
        std::process::exit(1);
    }

    let tuning = gossip_tuning(&cli);
    if let Err(error) = tuning.validate() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    info!(
        mode = %cli.mode,
        builder = cli.builder,
        seed = cli.seed,
        listen_port = cli.listen_port,
        peers = cli.peers.len(),
        payload_size_kib = cli.payload_size_kib,
        "ec-sim starting"
    );

    let (mut swarm, local_peer_id) = build_swarm(cli.seed, cli.listen_port, &tuning);
    info!(%local_peer_id, "swarm built");

    if let Some(path) = &cli.peer_list {
        match load_peer_list(path) {
            Ok(list) => info!(
                peers = list.peers.len(),
                path = %path.display(),
                "loaded peer list"
            ),
            Err(error) => {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
    }

    let topic = mesh_topic(cli.mode);
    match cli.mode {
        Mode::RsPartial => subscribe_partial(&mut swarm, &topic),
        Mode::RsSubnets => {
            for i in 0..NUM_COLUMNS {
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&column_topic(i))
                    .expect("subscribe to column topic");
            }
        }
        Mode::ChunkSubnets => {
            // Every chunk is required, so every node subscribes to every subnet.
            for i in 0..cli.gossipsub_chunk_count {
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&chunk_subnet_topic(i))
                    .expect("subscribe to chunk subnet topic");
            }
        }
        Mode::Hybrid => {
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .expect("subscribe to payload topic");
            if chunk_subscriber(cli.mode, cli.rs_subnet_subscriber) {
                for i in 0..NUM_COLUMNS {
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .subscribe(&column_topic(i))
                        .expect("subscribe to column topic");
                }
            }
        }
        Mode::Rlnc => {}
        _ => {
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .expect("subscribe to payload topic");
        }
    }
    info!(topic = %topic, "subscribed");

    dial_peers(&mut swarm, &cli.peers);

    let payload = make_payload(cli.seed, cli.payload_size_kib.saturating_mul(1024));
    let topics = TopicHashes::new();
    let mut mode_state = build_mode_state(&cli);

    let start = Instant::now();
    let warmup_min = Duration::from_secs(cli.warmup_secs);
    let warmup_timeout = Duration::from_secs(cli.warmup_secs.saturating_add(45));
    let observe = Duration::from_secs(cli.observe_secs);
    let mut tick = time::interval(Duration::from_millis(200));

    let mut warmup_done = false;
    let mut reconstructed = false;
    let mut observe_until: Option<Instant> = None;

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    &mut swarm,
                    event,
                    &mut reconstructed,
                    &topics,
                    cli.chunked_send_idontwant,
                    &mut mode_state,
                );
            }
            _ = tick.tick() => {
                let now = Instant::now();
                if !warmup_done {
                    let timed_out = now.duration_since(start) >= warmup_timeout;
                    let waited = now.duration_since(start) >= warmup_min;
                    if (waited && warmup_ready(&swarm, &cli, &tuning)) || timed_out {
                        let connected = swarm.connected_peers().count();
                        let mesh = mesh_peer_count(&swarm, &topic);
                        event!(
                            "warmup_complete",
                            connected = connected,
                            mesh = mesh,
                            timed_out = timed_out
                        );
                        warmup_done = true;
                        if cli.builder {
                            publish_payload(
                                &mut swarm,
                                &cli,
                                &payload,
                                &mut reconstructed,
                                &mut mode_state,
                            );
                        }
                        observe_until = Some(now + observe);
                    }
                } else if let Some(deadline) = observe_until {
                    if now >= deadline {
                        finish(&swarm, reconstructed, &mode_state);
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn dump_peer_ids_parses_without_builder() {
        let cli = Cli::try_parse_from(["ec-sim", "--dump-peer-ids", "7,8"]).unwrap();
        assert_eq!(cli.dump_peer_ids, vec![7, 8]);
        assert!(!cli.builder);
        assert!(cli.peer_list.is_none());
    }

    #[test]
    fn default_mode_is_gossipsub() {
        let cli = Cli::try_parse_from(["ec-sim"]).unwrap();
        assert_eq!(cli.mode, Mode::Gossipsub);
        assert!(gossip_tuning(&cli).validate().is_ok());
    }

    #[test]
    fn chunked_mode_defaults_to_sixty_four_chunks_and_its_lazy_gossip_setting() {
        let cli = Cli::try_parse_from([
            "ec-sim",
            "--mode",
            "gossipsub-chunked",
            "--chunked-gossip-lazy",
            "9",
        ])
        .unwrap();
        assert_eq!(cli.mode, Mode::GossipsubChunked);
        assert_eq!(cli.gossipsub_chunk_count, 64);
        assert!(!cli.chunked_send_idontwant);
        assert_eq!(gossip_tuning(&cli).gossip_lazy, 9);
    }

    #[test]
    fn chunked_mode_parses_idontwant_flag() {
        let cli = Cli::try_parse_from([
            "ec-sim",
            "--mode",
            "gossipsub-chunked",
            "--chunked-send-idontwant",
        ])
        .unwrap();
        assert!(cli.chunked_send_idontwant);
    }

    #[test]
    fn chunked_mode_rejects_zero_chunks() {
        assert!(Cli::try_parse_from([
            "ec-sim",
            "--mode",
            "gossipsub-chunked",
            "--gossipsub-chunk-count",
            "0",
        ])
        .is_err());
    }

    #[test]
    fn chunk_subnets_mode_reuses_the_chunk_count_and_sizes_its_topics() {
        let cli = Cli::try_parse_from([
            "ec-sim",
            "--mode",
            "chunk-subnets",
            "--gossipsub-chunk-count",
            "96",
        ])
        .unwrap();
        assert_eq!(cli.mode, Mode::ChunkSubnets);
        let tuning = gossip_tuning(&cli);
        assert_eq!(tuning.chunk_subnet_count, 96);
        assert!(tuning.validate().is_ok());
    }

    #[test]
    fn other_modes_configure_no_chunk_subnet_topics() {
        for mode in ["gossipsub", "gossipsub-chunked", "rs-subnets"] {
            let cli = Cli::try_parse_from(["ec-sim", "--mode", mode]).unwrap();
            assert_eq!(gossip_tuning(&cli).chunk_subnet_count, 0, "mode {mode}");
        }
    }

    #[test]
    fn chunk_subnets_mode_uses_its_own_topic_and_mesh_profile() {
        assert_eq!(
            mesh_topic(Mode::ChunkSubnets).to_string(),
            chunk_subnet_topic(0).to_string()
        );
        let tuning = GossipTuning {
            chunk_subnet: MeshTuning {
                mesh_n: 50,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            primary_mesh_tuning(Mode::ChunkSubnets, &tuning),
            tuning.chunk_subnet
        );
    }

    #[test]
    fn chunk_subnets_does_not_take_the_rs_subnet_role() {
        assert!(!chunk_subscriber(Mode::ChunkSubnets, true));
    }

    #[test]
    fn gossipsub_rs_defaults_to_the_standard_rate_and_its_own_topic() {
        let cli = Cli::try_parse_from(["ec-sim", "--mode", "gossipsub-rs"]).unwrap();
        assert_eq!(cli.mode, Mode::GossipsubRs);
        assert_eq!(gossipsub_rs_params(&cli), RsParams::DEFAULT);
        assert_eq!(
            mesh_topic(Mode::GossipsubRs).to_string(),
            payload_rs_topic().to_string()
        );
        // Single topic, so it must not be mistaken for a per-shard subnet.
        assert!(!chunk_subscriber(Mode::GossipsubRs, true));
        assert_eq!(column_from_topic(&payload_rs_topic().to_string()), None);
    }

    #[test]
    fn gossipsub_rs_accepts_a_custom_rate_and_uses_its_mesh_profile() {
        let cli = Cli::try_parse_from([
            "ec-sim",
            "--mode",
            "gossipsub-rs",
            "--gossipsub-rs-data-shards",
            "64",
            "--gossipsub-rs-total-shards",
            "80",
        ])
        .unwrap();
        let params = gossipsub_rs_params(&cli);
        assert_eq!(params, RsParams { data: 64, total: 80 });
        assert!(params.validate().is_ok());

        let tuning = GossipTuning {
            gossipsub_rs: MeshTuning {
                mesh_n: 33,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            primary_mesh_tuning(Mode::GossipsubRs, &tuning),
            tuning.gossipsub_rs
        );
    }

    #[test]
    fn gossipsub_rs_state_sizes_itself_to_the_configured_rate() {
        let cli = Cli::try_parse_from([
            "ec-sim",
            "--mode",
            "gossipsub-rs",
            "--gossipsub-rs-data-shards",
            "32",
            "--gossipsub-rs-total-shards",
            "48",
        ])
        .unwrap();
        match build_mode_state(&cli) {
            ModeState::GossipsubRs(state) => {
                assert_eq!(state.shards.len(), 48);
                assert_eq!(state.params.data, 32);
                // gossipsub-rs never bridges a full payload; that is hybrid's job.
                assert!(!state.bridge_payload);
            }
            _ => panic!("expected a gossipsub-rs state"),
        }
    }

    #[test]
    fn a_shard_is_merged_once_and_only_at_its_own_index() {
        let payload = make_payload(11, 4096);
        let params = RsParams::new(32, 48).unwrap();
        let (shard_len, hash, shards) = encode_payload_shards_with(&payload, params).unwrap();
        let message = |index: usize| ColumnShardMessage {
            index: index as u16,
            payload_len: payload.len() as u64,
            shard_len: shard_len as u64,
            payload_hash: hash,
            data: shards[index].clone(),
        };
        let mut state = RsSubnetState::with_params(params, false);

        assert_eq!(merge_rs_shard(&mut state, 0, message(0)), Some(1));
        // Duplicate index contributes nothing.
        assert_eq!(merge_rs_shard(&mut state, 0, message(0)), None);
        // Shard claiming an index other than where it arrived is rejected.
        assert_eq!(merge_rs_shard(&mut state, 1, message(2)), None);
        // Index beyond the configured rate is rejected.
        assert_eq!(merge_rs_shard(&mut state, 48, message(3)), None);
        assert_eq!(merge_rs_shard(&mut state, 1, message(1)), Some(2));
    }

    #[test]
    fn single_topic_suppression_batches_every_shard_id_into_one_topic() {
        // The per-column layout addresses a distinct topic per shard, while the
        // single-topic layout must reuse one topic for all of them.
        let per_column: Vec<_> = (0..4).map(|i| ShardTopics::PerColumn.topic_for(i)).collect();
        assert_eq!(
            per_column.iter().collect::<std::collections::HashSet<_>>().len(),
            4
        );
        let single: Vec<_> = (0..4).map(|i| ShardTopics::Single.topic_for(i)).collect();
        assert!(single.iter().all(|t| *t == payload_rs_topic().hash()));
    }

    #[test]
    fn each_chunk_lands_on_the_subnet_matching_its_index() {
        // The receive path accepts a chunk only when its index equals the subnet
        // parsed from the topic, so publishing must keep the two aligned.
        let payload = make_payload(42, 8 * 1024);
        let chunks = split_payload(&payload, 64).unwrap();
        assert_eq!(chunks.len(), 64);
        for (index, chunk) in chunks.iter().enumerate() {
            let topic = chunk_subnet_topic(index).to_string();
            assert_eq!(chunk_subnet_from_topic(&topic), Some(index));
            assert_eq!(chunk.index as usize, index);
        }
    }

    #[test]
    fn chunk_subnets_reconstructs_only_after_every_chunk_arrives() {
        let payload = make_payload(7, 8 * 1024);
        let mut chunks = split_payload(&payload, 64).unwrap();
        // Reverse arrival order: no erasure slack, so the last chunk decides.
        chunks.reverse();
        let mut assembler = GossipsubChunkAssembler::new();
        let last = chunks.pop().unwrap();
        for chunk in chunks {
            assert!(assembler.merge(chunk).payload.is_none());
        }
        assert_eq!(assembler.merge(last).payload, Some(payload));
    }

    #[test]
    fn hybrid_cli_assigns_the_chunk_subscriber_role() {
        let cli =
            Cli::try_parse_from(["ec-sim", "--mode", "hybrid", "--rs-subnet-subscriber"]).unwrap();
        assert_eq!(cli.mode, Mode::Hybrid);
        assert!(cli.rs_subnet_subscriber);
    }

    #[test]
    fn chunk_subscriber_only_enables_hybrid_role_or_rs_subnets() {
        assert!(chunk_subscriber(Mode::RsSubnets, false));
        assert!(chunk_subscriber(Mode::Hybrid, true));
        assert!(!chunk_subscriber(Mode::Hybrid, false));
        assert!(!chunk_subscriber(Mode::Gossipsub, true));
    }

    #[test]
    fn modes_use_their_topic_class_mesh_profile() {
        let tuning = GossipTuning {
            execution: MeshTuning {
                mesh_n: 10,
                ..Default::default()
            },
            subnet: MeshTuning {
                mesh_n: 20,
                ..Default::default()
            },
            partial: MeshTuning {
                mesh_n: 30,
                ..Default::default()
            },
            chunked: MeshTuning {
                mesh_n: 40,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(primary_mesh_tuning(Mode::Gossipsub, &tuning), tuning.execution);
        assert_eq!(primary_mesh_tuning(Mode::Hybrid, &tuning), tuning.execution);
        assert_eq!(primary_mesh_tuning(Mode::RsSubnets, &tuning), tuning.subnet);
        assert_eq!(primary_mesh_tuning(Mode::RsPartial, &tuning), tuning.partial);
        assert_eq!(
            primary_mesh_tuning(Mode::GossipsubChunked, &tuning),
            tuning.chunked
        );
    }

    #[test]
    fn hybrid_uses_the_payload_mesh() {
        assert_eq!(
            mesh_topic(Mode::Hybrid).to_string(),
            payload_topic().to_string()
        );
    }

    #[test]
    fn chunked_mode_uses_its_dedicated_topic() {
        assert_eq!(
            mesh_topic(Mode::GossipsubChunked).to_string(),
            payload_chunked_topic().to_string()
        );
    }

    #[test]
    fn payload_from_seed_is_deterministic() {
        let a = make_payload(42, 64);
        let b = make_payload(42, 64);
        let c = make_payload(43, 64);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(payload_hash(&a).len(), 64);
    }

    #[test]
    fn reconstructed_chunk_message_ids_match_published_chunks() {
        let payload = make_payload(42, 1024);
        let (shard_len, hash, shards) = encode_payload_shards(&payload).unwrap();
        let initial: Vec<_> = shards
            .iter()
            .take(PAYLOAD_DATA_SHARDS)
            .cloned()
            .enumerate()
            .collect();
        let (_, reconstructed_shards) =
            decode_payload_with(payload.len(), shard_len, &hash, &initial, RsParams::DEFAULT)
                .unwrap();

        for (index, (published, reconstructed)) in
            shards.iter().zip(reconstructed_shards.iter()).enumerate()
        {
            let topic = column_topic(index).hash();
            let published = ColumnShardMessage {
                index: index as u16,
                payload_len: payload.len() as u64,
                shard_len: shard_len as u64,
                payload_hash: hash,
                data: published.clone(),
            };
            let reconstructed = ColumnShardMessage {
                data: reconstructed.clone(),
                ..published.clone()
            };
            assert_eq!(
                content_message_id_for(&topic, &published.encode()),
                content_message_id_for(&topic, &reconstructed.encode())
            );
        }
    }
}
