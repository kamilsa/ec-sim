//! Random linear network coding over the Ristretto scalar field, with Pedersen
//! commitments and an ed25519 signature sidecar (builder's libp2p key).

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use libp2p::identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::coding::sha256;

const BYTES_PER_SCALAR: usize = 31;

/// One coded RLNC packet on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePacket {
    pub n: u16,
    pub m: u16,
    pub payload_len: u64,
    pub payload_hash: [u8; 32],
    pub coeffs: Vec<[u8; 32]>,
    pub w: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    pub builder_pk: Vec<u8>,
    pub signature: Vec<u8>,
}

impl WirePacket {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialize rlnc packet")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    pub fn encoded_len(&self) -> u64 {
        self.encode().len() as u64
    }
}

/// In-memory packet with field elements.
#[derive(Debug, Clone)]
pub struct Packet {
    pub n: usize,
    pub m: usize,
    pub payload_len: usize,
    pub payload_hash: [u8; 32],
    pub coeffs: Vec<Scalar>,
    pub w: Vec<Scalar>,
    pub commitments: Vec<RistrettoPoint>,
    pub builder_pk: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Packet {
    pub fn to_wire(&self) -> WirePacket {
        WirePacket {
            n: self.n as u16,
            m: self.m as u16,
            payload_len: self.payload_len as u64,
            payload_hash: self.payload_hash,
            coeffs: self.coeffs.iter().map(|s| s.to_bytes()).collect(),
            w: self.w.iter().map(|s| s.to_bytes()).collect(),
            commitments: self
                .commitments
                .iter()
                .map(|p| p.compress().to_bytes())
                .collect(),
            builder_pk: self.builder_pk.clone(),
            signature: self.signature.clone(),
        }
    }

    pub fn from_wire(p: &WirePacket) -> Option<Self> {
        let n = p.n as usize;
        let m = p.m as usize;
        if p.coeffs.len() != n || p.w.len() != m || p.commitments.len() != n {
            return None;
        }
        let coeffs = p
            .coeffs
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();
        let w = p
            .w
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();
        let mut commitments = Vec::with_capacity(n);
        for bytes in &p.commitments {
            commitments.push(CompressedRistretto(*bytes).decompress()?);
        }
        Some(Self {
            n,
            m,
            payload_len: p.payload_len as usize,
            payload_hash: p.payload_hash,
            coeffs,
            w,
            commitments,
            builder_pk: p.builder_pk.clone(),
            signature: p.signature.clone(),
        })
    }
}

fn generators(m: usize) -> Vec<RistrettoPoint> {
    (0..m)
        .map(|j| {
            let mut hasher = Sha512::new();
            hasher.update(b"ec-sim/rlnc/G/");
            hasher.update((j as u64).to_le_bytes());
            let digest = hasher.finalize();
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&digest);
            RistrettoPoint::from_uniform_bytes(&wide)
        })
        .collect()
}

fn commit(values: &[Scalar], gens: &[RistrettoPoint]) -> RistrettoPoint {
    RistrettoPoint::vartime_multiscalar_mul(values, gens)
}

fn sign_message(payload_hash: &[u8; 32], n: usize, m: usize, payload_len: usize, c: &[RistrettoPoint]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(payload_hash);
    msg.extend_from_slice(&(n as u64).to_le_bytes());
    msg.extend_from_slice(&(m as u64).to_le_bytes());
    msg.extend_from_slice(&(payload_len as u64).to_le_bytes());
    for point in c {
        msg.extend_from_slice(point.compress().as_bytes());
    }
    msg
}

fn pack(payload: &[u8], n: usize) -> (Vec<Vec<Scalar>>, usize) {
    let m = payload.len().div_ceil(n * BYTES_PER_SCALAR).max(1);
    let mut padded = payload.to_vec();
    padded.resize(n * m * BYTES_PER_SCALAR, 0);
    let mut vectors = vec![vec![Scalar::ZERO; m]; n];
    for i in 0..n {
        for j in 0..m {
            let start = (i * m + j) * BYTES_PER_SCALAR;
            let mut buf = [0u8; 32];
            buf[..BYTES_PER_SCALAR].copy_from_slice(&padded[start..start + BYTES_PER_SCALAR]);
            vectors[i][j] = Scalar::from_bytes_mod_order(buf);
        }
    }
    (vectors, m)
}

fn unpack(vectors: &[Vec<Scalar>], payload_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for row in vectors {
        for scalar in row {
            out.extend_from_slice(&scalar.to_bytes()[..BYTES_PER_SCALAR]);
        }
    }
    out.truncate(payload_len);
    out
}

fn random_scalar<R: rand::RngExt>(rng: &mut R) -> Scalar {
    let mut bytes = [0u8; 32];
    loop {
        rng.fill(&mut bytes);
        let s = Scalar::from_bytes_mod_order(bytes);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

/// Encode `payload` into `n` source packets, commit, and sign with `keypair`.
pub fn encode_source(payload: &[u8], n: usize, keypair: &identity::Keypair) -> Vec<Packet> {
    assert!(n >= 1, "need at least one RLNC chunk");
    let (vectors, m) = pack(payload, n);
    let gens = generators(m);
    let commitments: Vec<RistrettoPoint> = vectors.iter().map(|v| commit(v, &gens)).collect();
    let payload_hash = sha256(payload);
    let msg = sign_message(&payload_hash, n, m, payload.len(), &commitments);
    let signature = keypair.sign(&msg).expect("sign rlnc commitments");
    let builder_pk = keypair.public().encode_protobuf();
    (0..n)
        .map(|i| {
            let mut coeffs = vec![Scalar::ZERO; n];
            coeffs[i] = Scalar::ONE;
            Packet {
                n,
                m,
                payload_len: payload.len(),
                payload_hash,
                coeffs,
                w: vectors[i].clone(),
                commitments: commitments.clone(),
                builder_pk: builder_pk.clone(),
                signature: signature.clone(),
            }
        })
        .collect()
}

/// Verify the signature (unless `sig_cached`) and `Commit(w) == Σ b_i C_i`.
pub fn verify_packet(packet: &Packet, sig_cached: bool) -> bool {
    if packet.coeffs.len() != packet.n
        || packet.w.len() != packet.m
        || packet.commitments.len() != packet.n
    {
        return false;
    }
    if !sig_cached {
        let Ok(pk) = identity::PublicKey::try_decode_protobuf(&packet.builder_pk) else {
            return false;
        };
        let msg = sign_message(
            &packet.payload_hash,
            packet.n,
            packet.m,
            packet.payload_len,
            &packet.commitments,
        );
        if !pk.verify(&msg, &packet.signature) {
            return false;
        }
    }
    let gens = generators(packet.m);
    let left = commit(&packet.w, &gens);
    let right = commit(&packet.coeffs, &packet.commitments);
    left == right
}

/// Random linear combination of `packets`. Forwards the same C + signature.
pub fn recode<R: rand::RngExt>(packets: &[Packet], rng: &mut R) -> Option<Packet> {
    let first = packets.first()?;
    let n = first.n;
    let m = first.m;
    let mut coeffs = vec![Scalar::ZERO; n];
    let mut w = vec![Scalar::ZERO; m];
    for packet in packets {
        let r = random_scalar(rng);
        for i in 0..n {
            coeffs[i] += r * packet.coeffs[i];
        }
        for j in 0..m {
            w[j] += r * packet.w[j];
        }
    }
    Some(Packet {
        n,
        m,
        payload_len: first.payload_len,
        payload_hash: first.payload_hash,
        coeffs,
        w,
        commitments: first.commitments.clone(),
        builder_pk: first.builder_pk.clone(),
        signature: first.signature.clone(),
    })
}

/// Gaussian decoder: keeps an RREF basis of coefficient rows.
#[derive(Debug)]
pub struct Decoder {
    n: usize,
    m: usize,
    payload_len: usize,
    payload_hash: [u8; 32],
    basis: Vec<Option<(Vec<Scalar>, Vec<Scalar>)>>,
}

impl Decoder {
    pub fn new(n: usize, m: usize, payload_len: usize, payload_hash: [u8; 32]) -> Self {
        Self {
            n,
            m,
            payload_len,
            payload_hash,
            basis: vec![None; n],
        }
    }

    pub fn from_packet(packet: &Packet) -> Self {
        Self::new(packet.n, packet.m, packet.payload_len, packet.payload_hash)
    }

    pub fn rank(&self) -> usize {
        self.basis.iter().filter(|row| row.is_some()).count()
    }

    /// Insert `packet` if its coefficient row is independent. Returns whether
    /// the rank increased.
    pub fn insert(&mut self, packet: &Packet) -> bool {
        if packet.n != self.n || packet.m != self.m {
            return false;
        }
        let mut c = packet.coeffs.clone();
        let mut w = packet.w.clone();
        for col in 0..self.n {
            if let Some((bc, bw)) = &self.basis[col] {
                if c[col] != Scalar::ZERO {
                    let f = c[col];
                    for k in 0..self.n {
                        c[k] -= f * bc[k];
                    }
                    for k in 0..self.m {
                        w[k] -= f * bw[k];
                    }
                }
            }
        }
        let Some(pivot) = c.iter().position(|x| *x != Scalar::ZERO) else {
            return false;
        };
        let inv = c[pivot].invert();
        for k in 0..self.n {
            c[k] *= inv;
        }
        for k in 0..self.m {
            w[k] *= inv;
        }
        for col in 0..self.n {
            if col == pivot {
                continue;
            }
            if let Some((bc, bw)) = self.basis[col].as_mut() {
                if bc[pivot] != Scalar::ZERO {
                    let f = bc[pivot];
                    for k in 0..self.n {
                        bc[k] -= f * c[k];
                    }
                    for k in 0..self.m {
                        bw[k] -= f * w[k];
                    }
                }
            }
        }
        self.basis[pivot] = Some((c, w));
        true
    }

    pub fn decode(&self) -> Option<Vec<u8>> {
        if self.rank() < self.n {
            return None;
        }
        let mut vectors = Vec::with_capacity(self.n);
        for row in &self.basis {
            vectors.push(row.as_ref()?.1.clone());
        }
        let payload = unpack(&vectors, self.payload_len);
        if sha256(&payload) != self.payload_hash {
            return None;
        }
        Some(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_key() -> identity::Keypair {
        let mut secret = [7u8; 32];
        secret[31] = 1;
        identity::Keypair::ed25519_from_bytes(secret).expect("test key")
    }

    #[test]
    fn two_hop_recode_recovers_payload() {
        let payload: Vec<u8> = (0..200u8).collect();
        let key = test_key();
        let source = encode_source(&payload, 4, &key);
        let mut rng = StdRng::seed_from_u64(1);
        let mut hop1 = Vec::new();
        let mut decoder = Decoder::from_packet(&source[0]);
        while decoder.rank() < 4 {
            let packet = recode(&source, &mut rng).unwrap();
            assert!(verify_packet(&packet, decoder.rank() > 0));
            if decoder.insert(&packet) {
                hop1.push(packet);
            }
        }
        let hop2 = recode(&hop1, &mut rng).unwrap();
        assert!(verify_packet(&hop2, true));
        assert!(
            !decoder.insert(&hop2),
            "a recode of a full-rank set must be linearly dependent"
        );
        assert_eq!(decoder.decode().as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn dependent_packet_is_dropped() {
        let payload = vec![9u8; 80];
        let key = test_key();
        let source = encode_source(&payload, 3, &key);
        let mut decoder = Decoder::from_packet(&source[0]);
        assert!(decoder.insert(&source[0]));
        assert!(!decoder.insert(&source[0]));
        assert_eq!(decoder.rank(), 1);
    }

    #[test]
    fn tampered_body_fails_pedersen() {
        let payload = vec![4u8; 60];
        let key = test_key();
        let mut packet = encode_source(&payload, 3, &key).remove(0);
        packet.w[0] += Scalar::ONE;
        assert!(!verify_packet(&packet, true));
        packet.w[0] -= Scalar::ONE;
        assert!(verify_packet(&packet, true));
    }
}
