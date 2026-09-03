//! Networking layer: libp2p swarm with QUIC transport and Gossipsub.
//!
//! Builds and configures the swarm; the node loop in `main.rs` drives it.

use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identity,
    swarm::NetworkBehaviour,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
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
/// Modes 1–3 use `gossipsub` only. Mode 4 uses the RLNC push protocol on the
/// same QUIC connections.
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

/// Gossipsub fan-out tuning.
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
    /// Target mesh size (`D`).
    pub mesh_n: usize,
    /// Mesh low-water mark (`D_low`): below this the mesh is topped up.
    pub mesh_n_low: usize,
    /// Mesh high-water mark (`D_high`): above this the mesh is trimmed.
    pub mesh_n_high: usize,
    /// Minimum number of outbound peers to keep in the mesh.
    pub mesh_outbound_min: usize,
}

impl Default for GossipTuning {
    fn default() -> Self {
        Self {
            flood_publish: false,
            gossip_lazy: 0,
            gossip_factor: 0.0,
            mesh_n: 8,
            mesh_n_low: 6,
            mesh_n_high: 12,
            mesh_outbound_min: 2,
        }
    }
}

impl GossipTuning {
    /// Check the mesh inequalities gossipsub documents, for one
    /// `(outbound_min, n_low, n, n_high)` tuple.
    fn validate_mesh_tuple(
        outbound_min: usize,
        n_low: usize,
        n: usize,
        n_high: usize,
        label: &str,
    ) -> Result<(), String> {
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

    /// Check the mesh inequalities gossipsub documents.
    ///
    /// These are *not* enforced by `ConfigBuilder::build()` for a global mesh
    /// config, so an invalid combination would build cleanly and then misbehave
    /// at runtime.
    pub fn validate(&self) -> Result<(), String> {
        Self::validate_mesh_tuple(
            self.mesh_outbound_min,
            self.mesh_n_low,
            self.mesh_n,
            self.mesh_n_high,
            "gossipsub",
        )
    }
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

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_millis(700))
        .mesh_n_low(tuning.mesh_n_low)
        .mesh_n(tuning.mesh_n)
        .mesh_n_high(tuning.mesh_n_high)
        .mesh_outbound_min(tuning.mesh_outbound_min)
        .flood_publish(tuning.flood_publish)
        .gossip_lazy(tuning.gossip_lazy)
        .gossip_factor(tuning.gossip_factor)
        .history_length(5)
        .history_gossip(3)
        .max_transmit_size(16 * 1024 * 1024)
        .validation_mode(gossipsub::ValidationMode::Permissive)
        .build()
        .expect("valid gossipsub config");

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
            mesh_n_low: 9,
            ..Default::default()
        };
        assert!(low_above_n.validate().is_err());

        let n_above_high = GossipTuning {
            mesh_n: 20,
            ..Default::default()
        };
        assert!(n_above_high.validate().is_err());

        let outbound_above_low = GossipTuning {
            mesh_outbound_min: 7,
            ..Default::default()
        };
        assert!(outbound_above_low.validate().is_err());
    }

    #[test]
    fn outbound_min_cannot_exceed_half_the_mesh() {
        let tuning = GossipTuning {
            mesh_outbound_min: 2,
            mesh_n_low: 3,
            mesh_n: 3,
            mesh_n_high: 4,
            ..Default::default()
        };
        let err = tuning.validate().expect_err("2 * 2 > 3 must be rejected");
        assert!(err.contains("mesh_outbound_min * 2 <= mesh_n"), "{err}");
    }

    #[test]
    fn lighthouse_low_load_tier_is_expressible() {
        let tuning = GossipTuning {
            mesh_outbound_min: 1,
            mesh_n_low: 1,
            mesh_n: 3,
            mesh_n_high: 4,
            ..Default::default()
        };
        assert!(tuning.validate().is_ok(), "{:?}", tuning.validate());
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
}
