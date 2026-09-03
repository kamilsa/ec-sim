//! Payload-propagation simulator — Shadow-compatible entry point.
//!
//! One homogeneous network, one protocol per run. Connections warm up, the
//! builder publishes a single payload, every node observes for a window, then
//! exits.

#[macro_use]
mod events;
mod coding;
mod network;
mod payload_chunks;
mod rlnc;
mod rlnc_proto;

use crate::coding::{
    decode_payload, encode_payload_shards, ColumnShardMessage, PAYLOAD_DATA_SHARDS,
    PAYLOAD_TOTAL_SHARDS,
};
use crate::events::hex_bytes;
use crate::network::{
    build_swarm, column_from_topic, column_topic, dial_peers, gossip_byte_totals, keypair_from_seed,
    mesh_peer_count, payload_chunk_topic, payload_topic, subscribe_partial, GossipTuning,
    SimBehaviour, SimBehaviourEvent, NUM_COLUMNS,
};
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
use rand::{Rng, SeedableRng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::time::{self, Duration, Instant};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Propagation protocol selected for this run. Every peer speaks the same one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Mode {
    #[default]
    Gossipsub,
    #[value(name = "rs-partial")]
    RsPartial,
    #[value(name = "rs-subnets")]
    RsSubnets,
    Rlnc,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mode::Gossipsub => "gossipsub",
            Mode::RsPartial => "rs-partial",
            Mode::RsSubnets => "rs-subnets",
            Mode::Rlnc => "rlnc",
        })
    }
}

/// Shadow-compatible payload-propagation simulator.
#[derive(Parser, Debug)]
#[command(name = "ec-sim", version, about)]
struct Cli {
    /// Propagation mode. Every peer in the run speaks this protocol.
    #[arg(long, value_enum, default_value_t = Mode::Gossipsub)]
    mode: Mode,

    /// This node is the builder (publishes the payload once after warmup).
    #[arg(long, default_value_t = false)]
    builder: bool,

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

    /// Target mesh size (`D`).
    #[arg(long, default_value_t = 8)]
    mesh_n: usize,

    /// Mesh low-water mark (`D_low`).
    #[arg(long, default_value_t = 6)]
    mesh_n_low: usize,

    /// Mesh high-water mark (`D_high`).
    #[arg(long, default_value_t = 12)]
    mesh_n_high: usize,

    /// Minimum number of outbound peers to keep in the mesh.
    #[arg(long, default_value_t = 2)]
    mesh_outbound_min: usize,
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
        gossip_lazy: cli.gossip_lazy,
        gossip_factor: cli.gossip_factor,
        mesh_n: cli.mesh_n,
        mesh_n_low: cli.mesh_n_low,
        mesh_n_high: cli.mesh_n_high,
        mesh_outbound_min: cli.mesh_outbound_min,
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
        Mode::RsSubnets => column_topic(0),
        _ => payload_topic(),
    }
}

fn warmup_ready(swarm: &Swarm<SimBehaviour>, cli: &Cli, tuning: &GossipTuning) -> bool {
    let dial_count = cli.peers.len();
    if dial_count == 0 {
        return true;
    }
    let connected = swarm.connected_peers().count();
    let conn_ok = connected >= dial_count.min(tuning.mesh_n.max(1));
    if cli.mode == Mode::Rlnc {
        return conn_ok;
    }
    let mesh = mesh_peer_count(swarm, &mesh_topic(cli.mode));
    let mesh_ok = mesh >= tuning.mesh_n_low.min(connected.max(1));
    conn_ok && mesh_ok
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

fn publish_gossipsub(swarm: &mut Swarm<SimBehaviour>, payload: &[u8]) {
    match swarm
        .behaviour_mut()
        .gossipsub
        .publish(payload_topic(), payload.to_vec())
    {
        Ok(_) => {
            event!(
                "payload_published",
                bytes = payload.len(),
                hash = payload_hash(payload)
            );
        }
        Err(err) => warn!(%err, "gossipsub publish failed"),
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

struct RsSubnetState {
    shards: Vec<Option<Vec<u8>>>,
    payload_len: Option<usize>,
    shard_len: Option<usize>,
    payload_hash: Option<[u8; 32]>,
}

impl RsSubnetState {
    fn new() -> Self {
        Self {
            shards: vec![None; PAYLOAD_TOTAL_SHARDS],
            payload_len: None,
            shard_len: None,
            payload_hash: None,
        }
    }

    fn distinct(&self) -> usize {
        self.shards.iter().filter(|s| s.is_some()).count()
    }
}

fn publish_rs_subnets(
    swarm: &mut Swarm<SimBehaviour>,
    payload: &[u8],
    reconstructed: &mut bool,
) {
    let (shard_len, payload_hash, shards) = match encode_payload_shards(payload) {
        Ok(encoded) => encoded,
        Err(err) => {
            warn!(%err, "rs-subnets encode failed");
            return;
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
    event!(
        "payload_published",
        bytes = payload.len(),
        hash = hex_bytes(&payload_hash),
        shards = published,
        shard_len = shard_len
    );
    mark_reconstructed(reconstructed, payload);
}

fn handle_rs_subnets(
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
    if msg.index as usize != column || column >= PAYLOAD_TOTAL_SHARDS {
        return;
    }
    if state.shards[column].is_some() {
        return;
    }
    state.shards[column] = Some(msg.data);
    state.payload_len = Some(msg.payload_len as usize);
    state.shard_len = Some(msg.shard_len as usize);
    state.payload_hash = Some(msg.payload_hash);
    let distinct = state.distinct();
    event!(
        "shard_received",
        column = column,
        added = 1,
        distinct = distinct
    );
    if *reconstructed || distinct < PAYLOAD_DATA_SHARDS {
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
    match decode_payload(payload_len, shard_len, &hash, &present) {
        Ok((payload, _)) => mark_reconstructed(reconstructed, &payload),
        Err(err) => warn!(%err, "rs-subnets reconstruct failed"),
    }
}

fn handle_swarm_event(
    swarm: &mut Swarm<SimBehaviour>,
    event: SwarmEvent<SimBehaviourEvent>,
    reconstructed: &mut bool,
    payload_topic_hash: &gossipsub::TopicHash,
    chunk_topic_hash: &gossipsub::TopicHash,
    rs_partial: &mut Option<RsPartialState>,
    rs_subnets: &mut Option<RsSubnetState>,
    rlnc: &mut Option<RlncState>,
) {
    match event {
        SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            message,
            ..
        })) if message.topic == *payload_topic_hash => {
            mark_reconstructed(reconstructed, &message.data);
        }
        SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            message,
            ..
        })) => {
            if let Some(state) = rs_subnets.as_mut() {
                handle_rs_subnets(state, reconstructed, message.topic.as_str(), &message.data);
            }
        }
        SwarmEvent::Behaviour(SimBehaviourEvent::Gossipsub(gossipsub::Event::Partial {
            topic_hash,
            group_id,
            message,
            ..
        })) if topic_hash == *chunk_topic_hash => {
            if let Some(state) = rs_partial.as_mut() {
                handle_rs_partial(swarm, state, reconstructed, &group_id, message);
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
            if let Some(state) = rlnc.as_mut() {
                handle_rlnc_packet(swarm, state, reconstructed, peer, request);
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

fn pick_fanout(swarm: &Swarm<SimBehaviour>, exclude: Option<PeerId>, fanout: usize) -> Vec<PeerId> {
    let mut peers: Vec<PeerId> = swarm
        .connected_peers()
        .copied()
        .filter(|p| exclude != Some(*p))
        .collect();
    peers.sort();
    let take = fanout.min(peers.len());
    peers.truncate(take);
    peers
}

fn rlnc_push(swarm: &mut Swarm<SimBehaviour>, state: &mut RlncState, exclude: Option<PeerId>) {
    if state.held.is_empty() {
        return;
    }
    for peer in pick_fanout(swarm, exclude, state.fanout) {
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

fn finish(swarm: &Swarm<SimBehaviour>, reconstructed: bool, rlnc: &Option<RlncState>) {
    let (mut tx, mut rx) = gossip_byte_totals(swarm);
    if let Some(state) = rlnc {
        tx += state.tx;
        rx += state.rx;
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
        Mode::Gossipsub | Mode::RsPartial | Mode::RsSubnets | Mode::Rlnc
    ) {
        eprintln!("error: mode {} is not implemented yet", cli.mode);
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
    let payload_topic_hash = payload_topic().hash();
    let chunk_topic_hash = payload_chunk_topic().hash();
    let mut rs_partial = (cli.mode == Mode::RsPartial).then(|| RsPartialState {
        assembler: PayloadChunkAssembler::new(4),
        header_tracker: PayloadChunkHeaderTracker::new(4),
        recipients: cli.payload_chunk_recipients,
    });
    let mut rs_subnets = (cli.mode == Mode::RsSubnets).then(RsSubnetState::new);
    let mut rlnc_state = (cli.mode == Mode::Rlnc).then(|| {
        RlncState::new(cli.rlnc_chunks, cli.rlnc_fanout, cli.seed)
    });

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
                    &payload_topic_hash,
                    &chunk_topic_hash,
                    &mut rs_partial,
                    &mut rs_subnets,
                    &mut rlnc_state,
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
                            match cli.mode {
                                Mode::RsPartial => {
                                    if let Some(state) = rs_partial.as_mut() {
                                        publish_rs_partial(
                                            &mut swarm,
                                            state,
                                            &payload,
                                            &mut reconstructed,
                                        );
                                    }
                                }
                                Mode::RsSubnets => {
                                    publish_rs_subnets(&mut swarm, &payload, &mut reconstructed);
                                }
                                Mode::Rlnc => {
                                    if let Some(state) = rlnc_state.as_mut() {
                                        publish_rlnc(
                                            &mut swarm,
                                            state,
                                            &payload,
                                            &mut reconstructed,
                                            cli.seed,
                                        );
                                    }
                                }
                                _ => {
                                    publish_gossipsub(&mut swarm, &payload);
                                    mark_reconstructed(&mut reconstructed, &payload);
                                }
                            }
                        }
                        observe_until = Some(now + observe);
                    }
                } else if let Some(deadline) = observe_until {
                    if now >= deadline {
                        finish(&swarm, reconstructed, &rlnc_state);
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
    fn payload_from_seed_is_deterministic() {
        let a = make_payload(42, 64);
        let b = make_payload(42, 64);
        let c = make_payload(43, 64);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(payload_hash(&a).len(), 64);
    }
}
