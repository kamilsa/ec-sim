//! Networking layer: libp2p swarm with QUIC transport and Gossipsub.
//!
//! Builds and configures the swarm; the node loop in `main.rs` drives it.

use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identity,
    swarm::NetworkBehaviour,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::info;

/// Naive full-payload gossipsub topic (mode `gossipsub`).
pub const TOPIC_PAYLOAD: &str = "/ec/payload/1";

/// Reed-Solomon partial-message topic (mode `rs-partial`).
pub const TOPIC_PAYLOAD_CHUNKS: &str = "/ec/payload_chunks/1";

/// Number of column subnets (one gossipsub topic per RS shard).
pub const NUM_COLUMNS: usize = 128;

/// Gossipsub topic for the naive full-payload path.
pub fn payload_topic() -> IdentTopic {
    IdentTopic::new(TOPIC_PAYLOAD)
}

/// Gossipsub topic for the Reed-Solomon partial-message path.
pub fn payload_chunk_topic() -> IdentTopic {
    IdentTopic::new(TOPIC_PAYLOAD_CHUNKS)
}

/// Gossipsub topic for column subnet `column` (mode `rs-subnets`).
pub fn column_topic(column: usize) -> IdentTopic {
    IdentTopic::new(format!("/ec/payload_column/{column}/1"))
}

/// Parse `/ec/payload_column/{i}/1` into the column index.
pub fn column_from_topic(topic: &str) -> Option<usize> {
    let rest = topic.strip_prefix("/ec/payload_column/")?;
    let idx = rest.strip_suffix("/1")?;
    let column: usize = idx.parse().ok()?;
    (column < NUM_COLUMNS).then_some(column)
}

/// The composed libp2p behaviour for the simulator.
///
/// Gossipsub modes, including hybrid payload-and-subnet propagation, share the
/// same swarm. RLNC uses its push protocol on the same QUIC connections.
#[derive(NetworkBehaviour)]
pub struct SimBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub rlnc: crate::rlnc_proto::RlncBehaviour,
}

/// Build a deterministic libp2p keypair from a seed.
pub fn keypair_from_seed(seed: u64) -> identity::Keypair {
    // Stretch the u64 seed into 32 bytes for ed25519 secret key.
    let mut secret = [0u8; 32];
    let seed_bytes = seed.to_le_bytes();
    for (i, &b) in seed_bytes.iter().enumerate() {
        secret[i] = b;
        secret[i + 8] = b.wrapping_mul(31);
        secret[i + 16] = b.wrapping_mul(47);
        secret[i + 24] = b.wrapping_mul(59);
    }
    identity::Keypair::ed25519_from_bytes(secret).expect("valid ed25519 key from seed")
}

/// Mesh degrees for one class of gossipsub topics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshTuning {
    /// Target mesh size (`D`).
    pub mesh_n: usize,
    /// Mesh low-water mark (`D_low`): below this the mesh is topped up.
    pub mesh_n_low: usize,
    /// Mesh high-water mark (`D_high`): above this the mesh is trimmed.
    pub mesh_n_high: usize,
    /// Minimum number of outbound peers to keep in the mesh.
    pub mesh_outbound_min: usize,
}

impl Default for MeshTuning {
    fn default() -> Self {
        Self {
            mesh_n: 8,
            mesh_n_low: 6,
            mesh_n_high: 12,
            mesh_outbound_min: 2,
        }
    }
}

/// Gossipsub fan-out and per-topic mesh tuning.
///
/// Surfaced as configuration because the libp2p defaults differ from what
/// Ethereum clients run (`flood_publish = false`, mesh D=8).
pub struct GossipTuning {
    /// Publish to *every* subscribed peer instead of just `mesh_n` of them.
    /// libp2p defaults this to `true`; Ethereum clients turn it off.
    pub flood_publish: bool,
    /// Floor for the lazy-gossip peer count (`D_lazy`).
    pub gossip_lazy: usize,
    /// Fraction of non-mesh peers to gossip to.
    pub gossip_factor: f64,
    /// Mesh degrees for the full execution payload topic.
    pub execution: MeshTuning,
    /// Mesh degrees for every RS column subnet topic.
    pub subnet: MeshTuning,
    /// Mesh degrees for the RS partial-message topic.
    pub partial: MeshTuning,
}

impl Default for GossipTuning {
    fn default() -> Self {
        Self {
            flood_publish: false,
            gossip_lazy: 0,
            gossip_factor: 0.0,
            execution: MeshTuning::default(),
            subnet: MeshTuning::default(),
            partial: MeshTuning::default(),
        }
    }
}

impl GossipTuning {
    /// Check the mesh inequalities gossipsub documents, for one
    /// `(outbound_min, n_low, n, n_high)` tuple.
    fn validate_mesh_tuple(mesh: MeshTuning, label: &str) -> Result<(), String> {
        let MeshTuning {
            mesh_outbound_min: outbound_min,
            mesh_n_low: n_low,
            mesh_n: n,
            mesh_n_high: n_high,
        } = mesh;
        if !(outbound_min <= n_low && n_low <= n && n <= n_high) {
            return Err(format!(
                "{label} mesh parameters must satisfy \
                 mesh_outbound_min <= mesh_n_low <= mesh_n <= mesh_n_high, got {outbound_min} <= {n_low} <= {n} <= {n_high}"
            ));
        }
        if outbound_min * 2 > n {
            return Err(format!(
                "{label} mesh parameters must satisfy mesh_outbound_min * 2 <= mesh_n, \
                 got {outbound_min} * 2 > {n}"
            ));
        }
        Ok(())
    }

    /// Check the mesh inequalities gossipsub documents for every topic class.
    pub fn validate(&self) -> Result<(), String> {
        Self::validate_mesh_tuple(self.execution, "execution")?;
        Self::validate_mesh_tuple(self.subnet, "subnet")?;
        Self::validate_mesh_tuple(self.partial, "partial")
    }
}

fn configure_topic_mesh(
    builder: &mut gossipsub::ConfigBuilder,
    topic: gossipsub::TopicHash,
    tuning: MeshTuning,
) {
    builder
        .mesh_n_for_topic(tuning.mesh_n, topic.clone())
        .mesh_n_low_for_topic(tuning.mesh_n_low, topic.clone())
        .mesh_n_high_for_topic(tuning.mesh_n_high, topic.clone())
        .mesh_outbound_min_for_topic(tuning.mesh_outbound_min, topic);
}

fn content_message_id(message: &gossipsub::Message) -> gossipsub::MessageId {
    let topic = message.topic.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update((topic.len() as u64).to_le_bytes());
    hasher.update(topic);
    hasher.update(&message.data);
    gossipsub::MessageId::from(hasher.finalize().to_vec())
}

fn gossipsub_config(tuning: &GossipTuning) -> gossipsub::Config {
    let mut builder = gossipsub::ConfigBuilder::default();
    builder
        .heartbeat_interval(Duration::from_millis(700))
        // Use the execution mesh as the fallback for unexpected topics.
        .mesh_n_low(tuning.execution.mesh_n_low)
        .mesh_n(tuning.execution.mesh_n)
        .mesh_n_high(tuning.execution.mesh_n_high)
        .mesh_outbound_min(tuning.execution.mesh_outbound_min)
        .flood_publish(tuning.flood_publish)
        .gossip_lazy(tuning.gossip_lazy)
        .gossip_factor(tuning.gossip_factor)
        .history_length(5)
        .history_gossip(3)
        .max_transmit_size(16 * 1024 * 1024)
        // Reconstructed hybrid payloads have the original bytes. Give them the
        // same ID as the builder's publication so bridge attempts deduplicate.
        .message_id_fn(content_message_id)
        .validation_mode(gossipsub::ValidationMode::Permissive);
    configure_topic_mesh(&mut builder, payload_topic().hash(), tuning.execution);
    configure_topic_mesh(&mut builder, payload_chunk_topic().hash(), tuning.partial);
    for column in 0..NUM_COLUMNS {
        configure_topic_mesh(&mut builder, column_topic(column).hash(), tuning.subnet);
    }
    builder.build().expect("valid gossipsub config")
}

/// Build and configure the libp2p swarm.
///
/// Returns the swarm and the local `PeerId`.
pub fn build_swarm(
    seed: u64,
    listen_port: u16,
    tuning: &GossipTuning,
) -> (Swarm<SimBehaviour>, PeerId) {
    let keypair = keypair_from_seed(seed);
    let local_peer_id = PeerId::from(keypair.public());
    info!(%local_peer_id, "building swarm");

    let gossipsub_config = gossipsub_config(tuning);

    let gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .expect("valid gossipsub behaviour");

    let behaviour = SimBehaviour {
        gossipsub,
        rlnc: crate::rlnc_proto::rlnc_behaviour(),
    };

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_dns()
        .expect("valid DNS configuration")
        .with_behaviour(|_key| behaviour)
        .expect("valid behaviour")
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{listen_port}/quic-v1")
        .parse()
        .expect("valid multiaddr");

    let mut swarm = swarm;
    swarm.listen_on(listen_addr).expect("listen on QUIC");

    (swarm, local_peer_id)
}

/// Subscribe to a topic with the gossipsub 1.3 partial-message protocol enabled.
///
/// `enable_partials_for_topic` must be called *before* `subscribe` — the
/// behaviour ignores it once the topic is already in the mesh.
pub fn subscribe_partial(swarm: &mut Swarm<SimBehaviour>, topic: &IdentTopic) {
    let gossipsub = &mut swarm.behaviour_mut().gossipsub;
    gossipsub.enable_partials_for_topic(topic.hash(), true);
    gossipsub.subscribe(topic).expect("subscribe partial topic");
}

/// Dial a list of bootstrap peer multiaddrs.
pub fn dial_peers(swarm: &mut Swarm<SimBehaviour>, peers: &[Multiaddr]) {
    for addr in peers {
        info!(peer = %addr, "dialing peer");
        swarm.dial(addr.clone()).expect("dial peer");
    }
}

/// Number of mesh peers currently grafted on `topic`.
pub fn mesh_peer_count(swarm: &Swarm<SimBehaviour>, topic: &IdentTopic) -> usize {
    swarm
        .behaviour()
        .gossipsub
        .mesh_peers(&topic.hash())
        .count()
}

/// Cumulative gossipsub tx/rx bytes (payload + partial metadata + control).
pub fn gossip_byte_totals(swarm: &Swarm<SimBehaviour>) -> (u64, u64) {
    fn dir_total(c: &gossipsub::TrafficCounters) -> u64 {
        c.data_bytes + c.meta_bytes + c.control_bytes.iter().sum::<u64>()
    }
    let stats = swarm.behaviour().gossipsub.traffic();
    let mut tx = dir_total(&stats.untopiced.tx);
    let mut rx = dir_total(&stats.untopiced.rx);
    for (_, d) in &stats.per_topic {
        tx += dir_total(&d.tx);
        rx += dir_total(&d.rx);
    }
    (tx, rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_from_seed_is_deterministic() {
        let a = PeerId::from(keypair_from_seed(42).public());
        let b = PeerId::from(keypair_from_seed(42).public());
        let c = PeerId::from(keypair_from_seed(43).public());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn default_tuning_is_valid() {
        assert!(GossipTuning::default().validate().is_ok());
    }

    #[test]
    fn ordering_violations_are_rejected() {
        let low_above_n = GossipTuning {
            execution: MeshTuning {
                mesh_n_low: 9,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(low_above_n.validate().is_err());

        let n_above_high = GossipTuning {
            subnet: MeshTuning {
                mesh_n: 20,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(n_above_high.validate().is_err());

        let outbound_above_low = GossipTuning {
            partial: MeshTuning {
                mesh_outbound_min: 7,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(outbound_above_low.validate().is_err());
    }

    #[test]
    fn outbound_min_cannot_exceed_half_the_mesh() {
        let tuning = GossipTuning {
            subnet: MeshTuning {
                mesh_outbound_min: 2,
                mesh_n_low: 3,
                mesh_n: 3,
                mesh_n_high: 4,
            },
            ..Default::default()
        };
        let err = tuning.validate().expect_err("2 * 2 > 3 must be rejected");
        assert!(err.contains("mesh_outbound_min * 2 <= mesh_n"), "{err}");
    }

    #[test]
    fn lighthouse_low_load_tier_is_expressible() {
        let tuning = GossipTuning {
            partial: MeshTuning {
                mesh_outbound_min: 1,
                mesh_n_low: 1,
                mesh_n: 3,
                mesh_n_high: 4,
            },
            ..Default::default()
        };
        assert!(tuning.validate().is_ok(), "{:?}", tuning.validate());
    }

    #[test]
    fn topic_classes_receive_independent_mesh_profiles() {
        let tuning = GossipTuning {
            execution: MeshTuning {
                mesh_n: 80,
                mesh_n_low: 60,
                mesh_n_high: 90,
                mesh_outbound_min: 18,
            },
            subnet: MeshTuning {
                mesh_n: 8,
                mesh_n_low: 4,
                mesh_n_high: 12,
                mesh_outbound_min: 2,
            },
            partial: MeshTuning {
                mesh_n: 40,
                mesh_n_low: 30,
                mesh_n_high: 50,
                mesh_outbound_min: 10,
            },
            ..Default::default()
        };
        let config = gossipsub_config(&tuning);

        for (topic, expected) in [
            (payload_topic(), tuning.execution),
            (payload_chunk_topic(), tuning.partial),
            (column_topic(0), tuning.subnet),
            (column_topic(NUM_COLUMNS - 1), tuning.subnet),
        ] {
            let hash = topic.hash();
            assert_eq!(config.mesh_n_for_topic(&hash), expected.mesh_n);
            assert_eq!(config.mesh_n_low_for_topic(&hash), expected.mesh_n_low);
            assert_eq!(config.mesh_n_high_for_topic(&hash), expected.mesh_n_high);
            assert_eq!(
                config.mesh_outbound_min_for_topic(&hash),
                expected.mesh_outbound_min
            );
        }
    }

    #[test]
    fn payload_message_ids_ignore_publisher_and_sequence() {
        let config = gossipsub_config(&GossipTuning::default());
        let data = b"reconstructed payload".to_vec();
        let builder_message = gossipsub::Message {
            source: Some(PeerId::from(keypair_from_seed(42).public())),
            data: data.clone(),
            sequence_number: Some(1),
            topic: payload_topic().hash(),
        };
        let bridged_message = gossipsub::Message {
            source: Some(PeerId::from(keypair_from_seed(43).public())),
            data,
            sequence_number: Some(99),
            topic: payload_topic().hash(),
        };

        assert_eq!(
            config.message_id(&builder_message),
            config.message_id(&bridged_message)
        );
    }

    #[test]
    fn content_message_ids_include_topic_and_payload() {
        let config = gossipsub_config(&GossipTuning::default());
        let message = gossipsub::Message {
            source: Some(PeerId::from(keypair_from_seed(42).public())),
            data: b"payload".to_vec(),
            sequence_number: Some(1),
            topic: payload_topic().hash(),
        };
        let different_topic = gossipsub::Message {
            topic: column_topic(0).hash(),
            ..message.clone()
        };
        let different_payload = gossipsub::Message {
            data: b"other payload".to_vec(),
            ..message.clone()
        };

        assert_ne!(
            config.message_id(&message),
            config.message_id(&different_topic)
        );
        assert_ne!(
            config.message_id(&message),
            config.message_id(&different_payload)
        );
    }

    #[test]
    fn column_topic_round_trips() {
        for i in [0usize, 1, 63, 127] {
            let topic = column_topic(i);
            assert_eq!(column_from_topic(&topic.to_string()), Some(i));
        }
        assert_eq!(column_from_topic("/ec/payload_column/128/1"), None);
        assert_eq!(column_from_topic("/ec/payload/1"), None);
        assert_eq!(column_from_topic("/ec/payload_column/7"), None);
    }

    #[test]
    fn every_payload_shard_has_a_column_topic() {
        assert_eq!(NUM_COLUMNS, crate::coding::PAYLOAD_TOTAL_SHARDS);
    }
}
