#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Launch an ec-sim network simulation under Shadow.

Reads a TOML config (default `ecsim.toml`), generates a geo-realistic Shadow
topology (`topology.gml`) and a `shadow.yaml` wiring every node's QUIC peers,
then runs the simulation either:
  - in Docker  ([run].runner = "docker"): builds an image with ec-sim on top of a
    Shadow base image and runs Shadow in a container; or
  - natively   ([run].runner = "native"): builds ec-sim with `cargo build --release`
    and runs a `shadow` binary from PATH.

Usage:
  uv run shadow-sim.py                      # build (if needed) + run with ecsim.toml
  uv run shadow-sim.py my.toml              # use a different config file
  uv run shadow-sim.py --dry-run            # generate shadow.yaml/topology.gml only
  uv run shadow-sim.py --rebuild            # force `docker build` first
  uv run shadow-sim.py my.toml --clean      # wipe shadow.data/, history, and summary.html

Results land in `<output.dir>/shadow.data/hosts/<host>/ec-sim.1000.stdout`.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

CL_PORT = 9000  # libp2p QUIC (UDP)

EC_SIM_BIN_DOCKER = "/opt/ecsim/ec-sim"
EC_SIM_BIN_NATIVE = str(REPO_ROOT / "target" / "release" / "ec-sim")

MODES = {"gossipsub", "rs-partial", "rs-subnets", "hybrid", "rlnc"}
HYBRID_SELECTIONS = {"fraction", "supernodes"}
DEFAULT_MODE = "gossipsub"
DEFAULT_FLOOD_PUBLISH = False
DEFAULT_GOSSIP_LAZY = 0
DEFAULT_GOSSIP_FACTOR = 0.0
MESH_PROFILES = ("execution", "subnet", "partial")
LEGACY_MESH_KEYS = ("mesh_n", "mesh_n_low", "mesh_n_high", "mesh_outbound_min")
DEFAULT_MESH_N = 8
DEFAULT_MESH_N_LOW = 6
DEFAULT_MESH_N_HIGH = 12
DEFAULT_MESH_OUTBOUND_MIN = 2
DEFAULT_PAYLOAD_SIZE_KIB = 256
DEFAULT_WARMUP_SECS = 15
DEFAULT_OBSERVE_SECS = 20
DEFAULT_PAYLOAD_CHUNK_RECIPIENTS = 4
DEFAULT_RLNC_CHUNKS = 10
DEFAULT_RLNC_FANOUT = 40
DEFAULT_HYBRID_SELECTION = "fraction"
DEFAULT_HYBRID_RS_SUBNET_FRACTION = 0.0
DEFAULT_NODES = 128
DEFAULT_PEERS_PER_NODE = 50

# Inter-region round-trip latencies in milliseconds, ported from blobsim /
# lean-shadow-fuzzer. generate_gml writes these as Shadow's one-way edge latency
# (matching blobsim, including the commented-out RTT/2 on inter-host edges).
REGIONS_LATENCY_MS: dict[str, dict[str, int]] = {
    "us-east": {"us-east": 20, "us-west": 60, "europe": 80, "asia": 150, "sa": 120, "africa": 180},
    "us-west": {"us-east": 60, "us-west": 20, "europe": 130, "asia": 110, "sa": 160, "africa": 200},
    "europe": {"us-east": 80, "us-west": 130, "europe": 15, "asia": 100, "sa": 170, "africa": 80},
    "asia": {"us-east": 150, "us-west": 110, "europe": 100, "asia": 20, "sa": 250, "africa": 160},
    "sa": {"us-east": 120, "us-west": 160, "europe": 170, "asia": 250, "sa": 25, "africa": 220},
    "africa": {"us-east": 180, "us-west": 200, "europe": 80, "asia": 160, "sa": 220, "africa": 30},
}


def log(msg: str) -> None:
    print(f"[shadow-sim] {msg}", flush=True)


def die(msg: str) -> None:
    print(f"[shadow-sim] error: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def mode_setting(sim: dict) -> str:
    mode = sim.get("mode", DEFAULT_MODE)
    if not isinstance(mode, str) or mode not in MODES:
        die(f"[sim].mode must be one of: {', '.join(sorted(MODES))}")
    return mode


def hybrid_settings(sim: dict) -> tuple[str, float]:
    selection = sim.get("hybrid_selection", DEFAULT_HYBRID_SELECTION)
    if not isinstance(selection, str) or selection not in HYBRID_SELECTIONS:
        die("[sim].hybrid_selection must be one of: "
            f"{', '.join(sorted(HYBRID_SELECTIONS))}")
    fraction = sim.get("hybrid_rs_subnet_fraction", DEFAULT_HYBRID_RS_SUBNET_FRACTION)
    if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not 0 <= fraction <= 1:
        die("[sim].hybrid_rs_subnet_fraction must be a number between 0 and 1")
    return selection, float(fraction)


def gossip_tuning_settings(sim: dict) -> tuple[bool, int, float]:
    flood = sim.get("flood_publish", DEFAULT_FLOOD_PUBLISH)
    if not isinstance(flood, bool):
        die("[sim].flood_publish must be true or false")
    lazy = sim.get("gossip_lazy", DEFAULT_GOSSIP_LAZY)
    if isinstance(lazy, bool) or not isinstance(lazy, int) or lazy < 0:
        die("[sim].gossip_lazy must be a non-negative integer")
    factor = sim.get("gossip_factor", DEFAULT_GOSSIP_FACTOR)
    if isinstance(factor, bool) or not isinstance(factor, (int, float)) or factor < 0:
        die("[sim].gossip_factor must be a non-negative number")
    return flood, lazy, float(factor)


def mesh_settings(sim: dict, profile: str) -> tuple[int, int, int, int]:
    if profile not in MESH_PROFILES:
        raise ValueError(f"unknown mesh profile: {profile}")
    legacy = [key for key in LEGACY_MESH_KEYS if key in sim]
    if legacy:
        die("[sim] generic mesh settings were replaced; use "
            f"{profile}_mesh_* (remove: {', '.join(legacy)})")

    def _count(key: str, default: int) -> int:
        value = sim.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            die(f"[sim].{key} must be a non-negative integer")
        return value

    prefix = f"{profile}_mesh"
    mesh_n = _count(f"{prefix}_n", DEFAULT_MESH_N)
    low = _count(f"{prefix}_n_low", DEFAULT_MESH_N_LOW)
    high = _count(f"{prefix}_n_high", DEFAULT_MESH_N_HIGH)
    outbound = _count(f"{prefix}_outbound_min", DEFAULT_MESH_OUTBOUND_MIN)

    if not (outbound <= low <= mesh_n <= high):
        die(f"[sim] {profile} mesh parameters must satisfy {prefix}_outbound_min <= "
            f"{prefix}_n_low <= {prefix}_n <= {prefix}_n_high, got {outbound} <= {low} <= "
            f"{mesh_n} <= {high}")
    if outbound * 2 > mesh_n:
        die(f"[sim] {profile} mesh parameters must satisfy {prefix}_outbound_min * 2 <= "
            f"{prefix}_n, got {outbound} * 2 > {mesh_n}")
    return mesh_n, low, high, outbound


def _positive_int(sim: dict, key: str, default: int) -> int:
    value = sim.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        die(f"[sim].{key} must be a positive integer")
    return value


def _nonneg_int(sim: dict, key: str, default: int) -> int:
    value = sim.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        die(f"[sim].{key} must be a non-negative integer")
    return value


class Node:
    """One simulated host: a Shadow host + an ec-sim process."""

    def __init__(self, index: int, name: str, is_builder: bool):
        self.index = index
        self.name = name
        self.is_builder = is_builder
        self.ip = ""
        self.region = ""
        self.bandwidth_up = ""
        self.bandwidth_down = ""
        self.is_supernode = False
        self.is_rs_subnet_subscriber = False


def build_nodes(cfg: dict) -> list[Node]:
    n = int(cfg["topology"].get("nodes", DEFAULT_NODES))
    if n < 1:
        die("[topology].nodes must be >= 1")
    width = max(3, len(str(n - 1)))
    nodes = [Node(i, f"node{i:0{width}d}", is_builder=(i == 0)) for i in range(n)]
    base = ipaddress.ip_address("11.0.0.1")
    for node in nodes:
        node.ip = str(base + node.index)
    return nodes


def weighted_assign(weights: dict[str, float], count: int, rng: random.Random) -> list[str]:
    keys = list(weights.keys())
    vals = list(weights.values())
    return [rng.choices(keys, weights=vals, k=1)[0] for _ in range(count)]


def assign_supernodes(nodes: list[Node], fraction: float, rng: random.Random) -> int:
    count = int(len(nodes) * fraction + 0.5)
    if count > 0:
        for node in rng.sample(nodes, count):
            node.is_supernode = True
    return count


def assign_hybrid_subscribers(nodes: list[Node], mode: str, selection: str,
                              fraction: float, seed: int) -> list[Node]:
    """Select chunk subscribers without perturbing topology RNG streams."""
    if mode != "hybrid":
        return []

    if selection == "supernodes":
        selected = [nodes[0]]
        selected.extend(node for node in nodes[1:] if node.is_supernode)
        if len(selected) < 2:
            die("[sim].hybrid_selection = \"supernodes\" requires at least one "
                "supernode besides the builder")
    else:
        count = int(len(nodes) * fraction + 0.5)
        if count < 2:
            die("[sim].hybrid_rs_subnet_fraction must select at least two chunk subscribers")
        selected = [nodes[0]]
        selected.extend(random.Random(seed + 2).sample(nodes[1:], count - 1))

    for node in selected:
        node.is_rs_subnet_subscriber = True
    return selected


def generate_gml(nodes: list[Node], jitter_ratio: float, packet_loss: float,
                 rng: random.Random) -> str:
    n = len(nodes)
    lines: list[str] = ["graph [", "  directed 0"]

    for node in nodes:
        lines += [
            "  node [",
            f"    id {node.index}",
            f'    host_bandwidth_up "{node.bandwidth_up}"',
            f'    host_bandwidth_down "{node.bandwidth_down}"',
            f'    label "{node.name}"',
            f'    region "{node.region}"',
            "  ]",
        ]

    switch_id = n
    lines += [
        "  node [",
        f"    id {switch_id}",
        '    host_bandwidth_up "10 Gbit"',
        '    host_bandwidth_down "10 Gbit"',
        '    label "switch"',
        "  ]",
    ]

    for node in nodes:
        lines += ["  edge [", f"    source {node.index}", f"    target {node.index}",
                  '    latency "1 ms"', f"    packet_loss {packet_loss}", "  ]"]
    lines += ["  edge [", f"    source {switch_id}", f"    target {switch_id}",
              '    latency "1 ms"', f"    packet_loss {packet_loss}", "  ]"]

    for node in nodes:
        base_ms = REGIONS_LATENCY_MS[node.region][node.region] * 0.5
        jitter = base_ms * jitter_ratio * (rng.random() * 2 - 1)
        latency = max(0.5, base_ms + jitter)
        lines += ["  edge [", f"    source {node.index}", f"    target {switch_id}",
                  f'    latency "{max(1, round(latency))} ms"',
                  f"    packet_loss {packet_loss}", "  ]"]

    # Full inter-host mesh. Copied from blobsim, including the commented-out
    # RTT/2 on inter-host edges (those use the table value as written).
    for i in range(n):
        ri = nodes[i].region
        for j in range(i + 1, n):
            rj = nodes[j].region
            base_ms = REGIONS_LATENCY_MS[ri].get(rj, 200)  # * 0.5
            jitter = base_ms * jitter_ratio * (rng.random() * 2 - 1)
            latency = max(0.5, base_ms + jitter)
            lines += ["  edge [", f"    source {i}", f"    target {j}",
                      f'    latency "{max(1, round(latency))} ms"',
                      f"    packet_loss {packet_loss}", "  ]"]

    lines.append("]")
    return "\n".join(lines) + "\n"


def wire_peers(nodes: list[Node], peers_per_node: int,
               rng: random.Random) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for node in nodes:
        candidates = [p for p in nodes if p.index != node.index]
        chosen = rng.sample(candidates, min(peers_per_node, len(candidates)))
        out[node.index] = [f"/ip4/{p.ip}/udp/{CL_PORT}/quic-v1" for p in chosen]
    return out


def dump_peer_ids(seeds: list[int], ec_sim_bin: str, image: str | None) -> list[str] | None:
    if not seeds:
        return []
    seed_arg = ",".join(str(s) for s in seeds)
    if ec_sim_bin == EC_SIM_BIN_DOCKER:
        if not image or not image_exists(image):
            return None
        cmd = ["docker", "run", "--rm", "--platform", "linux/arm64",
               "--entrypoint", EC_SIM_BIN_DOCKER, image,
               "--dump-peer-ids", seed_arg]
    else:
        if not Path(ec_sim_bin).is_file():
            return None
        cmd = [ec_sim_bin, "--dump-peer-ids", seed_arg]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip() or f"exit {result.returncode}"
        die(f"ec-sim --dump-peer-ids failed: {err}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def write_peers_json(nodes: list[Node], cfg: dict, out_dir: Path, ec_sim_bin: str,
                     image: str | None) -> Path | None:
    sim = cfg["sim"]
    seeds = [int(sim["seed"]) + node.index for node in nodes]
    peer_ids = dump_peer_ids(seeds, ec_sim_bin, image)
    if peer_ids is None:
        log("skipping peers.json (ec-sim binary/image not available)")
        return None
    if len(peer_ids) != len(nodes):
        die(f"--dump-peer-ids returned {len(peer_ids)} ids, expected {len(nodes)}")
    peers = []
    for node, peer_id in zip(nodes, peer_ids):
        peers.append({
            "name": node.name,
            "peer_id": peer_id,
            "addr": f"/ip4/{node.ip}/udp/{CL_PORT}/quic-v1",
        })
    path = out_dir / "peers.json"
    path.write_text(json.dumps({"peers": peers}, indent=2) + "\n")
    log(f"  wrote {path.name} ({len(peers)} peers)")
    return path


def build_args(node: Node, cfg: dict, peers: list[str],
               peer_list: Path | None = None) -> str:
    sim = cfg["sim"]
    seed = int(sim["seed"]) + node.index
    parts: list[str] = [
        "--mode", mode_setting(sim),
        "--seed", str(seed),
        "--listen-port", str(CL_PORT),
        "--payload-size-kib", str(_positive_int(sim, "payload_size_kib", DEFAULT_PAYLOAD_SIZE_KIB)),
        "--warmup-secs", str(_nonneg_int(sim, "warmup_secs", DEFAULT_WARMUP_SECS)),
        "--observe-secs", str(_nonneg_int(sim, "observe_secs", DEFAULT_OBSERVE_SECS)),
        "--payload-chunk-recipients",
        str(_positive_int(sim, "payload_chunk_recipients", DEFAULT_PAYLOAD_CHUNK_RECIPIENTS)),
        "--rlnc-chunks", str(_positive_int(sim, "rlnc_chunks", DEFAULT_RLNC_CHUNKS)),
        "--rlnc-fanout", str(_positive_int(sim, "rlnc_fanout", DEFAULT_RLNC_FANOUT)),
    ]
    if node.is_builder:
        parts.append("--builder")
    if node.is_rs_subnet_subscriber:
        parts.append("--rs-subnet-subscriber")
    if peer_list is not None:
        parts += ["--peer-list", str(peer_list)]
    flood, lazy, factor = gossip_tuning_settings(sim)
    if flood:
        parts.append("--flood-publish")
    parts += ["--gossip-lazy", str(lazy), "--gossip-factor", str(factor)]
    for profile in MESH_PROFILES:
        mesh_n, mesh_low, mesh_high, mesh_outbound = mesh_settings(sim, profile)
        parts += [f"--{profile}-mesh-n", str(mesh_n),
                  f"--{profile}-mesh-n-low", str(mesh_low),
                  f"--{profile}-mesh-n-high", str(mesh_high),
                  f"--{profile}-mesh-outbound-min", str(mesh_outbound)]
    for p in peers:
        parts += ["--peer", p]
    return " ".join(parts)


def generate_shadow_yaml(nodes: list[Node], cfg: dict, gml_path: Path,
                         peers: dict[int, list[str]],
                         ec_sim_bin: str,
                         peer_list: Path | None = None) -> str:
    sim = cfg["sim"]
    warmup = _nonneg_int(sim, "warmup_secs", DEFAULT_WARMUP_SECS)
    observe = _nonneg_int(sim, "observe_secs", DEFAULT_OBSERVE_SECS)
    stop_time = sim.get("stop_time") or f"{warmup + observe + 60}s"
    rust_log = str(sim.get("rust_log", "info"))

    out: list[str] = [
        "# Auto-generated by shadow-sim.py — do not edit by hand.",
        "general:",
        f"  stop_time: {stop_time}",
        "  model_unblocked_syscall_latency: true",
        "",
        "network:",
        "  use_shortest_path: true",
        "  graph:",
        "    type: gml",
        "    file:",
        f"      path: {gml_path}",
        "",
        "hosts:",
    ]
    for node in nodes:
        args = build_args(node, cfg, peers.get(node.index, []), peer_list)
        out += [
            f"  {node.name}:",
            f"    network_node_id: {node.index}",
            f"    ip_addr: {node.ip}",
            f'    bandwidth_up: "{node.bandwidth_up}"',
            f'    bandwidth_down: "{node.bandwidth_down}"',
            "    processes:",
            f"    - path: {ec_sim_bin}",
            f'      args: "{args}"',
            "      start_time: 1s",
            "      expected_final_state: {exited: 0}",
            "      environment:",
            f'        RUST_LOG: "{rust_log}"',
        ]
    return "\n".join(out) + "\n"


def image_exists(image: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", image],
                          capture_output=True).returncode == 0


def docker_build(image: str, shadow_image: str) -> None:
    log(f"building image {image} on base {shadow_image} (docker build --no-cache, arm64)...")
    subprocess.run(
        ["docker", "build", "--no-cache", "--platform", "linux/arm64",
         "-f", str(REPO_ROOT / "docker" / "Dockerfile"),
         "--build-arg", f"SHADOW_IMAGE={shadow_image}",
         "-t", image, str(REPO_ROOT)],
        check=True,
    )


def cargo_build_release() -> None:
    if shutil.which("cargo") is None:
        die("`cargo` not found in PATH — needed to build ec-sim for the native runner.")
    log("building ec-sim (cargo build --release)...")
    subprocess.run(["cargo", "build", "--release"], cwd=REPO_ROOT, check=True)


def native_run_shadow(out_dir: Path) -> None:
    if shutil.which("shadow") is None:
        die("`shadow` not found in PATH. Install Shadow (https://shadow.github.io/) "
            'or use the Docker runner ([run].runner = "docker").')
    shadow_data = out_dir / "shadow.data"
    shadow_yaml = out_dir / "shadow.yaml"
    log("running Shadow natively...")
    subprocess.run(
        ["shadow", "-d", str(shadow_data), "--progress", "true", str(shadow_yaml)],
        cwd=out_dir, check=True,
    )


def docker_run_shadow(image: str, out_dir: Path) -> None:
    subprocess.run(["docker", "rm", "-f", "ecsim-shadow-run"],
                   check=False, capture_output=True)
    shadow_data = out_dir / "shadow.data"
    shadow_yaml = out_dir / "shadow.yaml"
    log("running Shadow in container...")
    subprocess.run(
        ["docker", "run", "--rm", "--name", "ecsim-shadow-run",
         "--platform", "linux/arm64",
         "--security-opt", "seccomp=unconfined",
         "--shm-size", "4g",
         "-v", f"{out_dir}:{out_dir}",
         "-w", str(out_dir),
         "--entrypoint", "/bin/bash", image,
         "-c", f"shadow -d {shadow_data} --progress true {shadow_yaml}"],
        check=True,
    )


_ANSI = re.compile(r"\x1b\[[0-9;]*[mK]")


def summarize(out_dir: Path) -> None:
    hosts_dir = out_dir / "shadow.data" / "hosts"
    if not hosts_dir.is_dir():
        log(f"no shadow.data/hosts under {out_dir} — nothing to summarize.")
        return

    n_hosts = 0
    warmup = 0
    published = 0
    reconstructed = 0
    run_end = 0
    reconstructed_true = 0

    for host in sorted(hosts_dir.iterdir()):
        stdout = host / "ec-sim.1000.stdout"
        if not stdout.is_file():
            continue
        n_hosts += 1
        text = _ANSI.sub("", stdout.read_text(errors="replace"))
        if "EVENT kind=warmup_complete" in text:
            warmup += 1
        if "EVENT kind=payload_published" in text:
            published += 1
        if "EVENT kind=payload_reconstructed" in text:
            reconstructed += 1
        if "EVENT kind=run_end" in text:
            run_end += 1
            if "reconstructed=true" in text:
                reconstructed_true += 1

    log("── run summary ─────────────────────────────────────────────")
    log(f"hosts: {n_hosts}  warmup_complete: {warmup}  published: {published}")
    log(f"reconstructed: {reconstructed}/{n_hosts}  run_end: {run_end}  "
        f"run_end reconstructed=true: {reconstructed_true}")
    log("────────────────────────────────────────────────────────────")


def _generate_run(cfg: dict, out_dir: Path, seed: int,
                  ec_sim_bin: str, image: str | None = None) -> tuple[int, dict]:
    cfg["sim"]["seed"] = seed
    net = cfg["network"]
    jitter_ratio = float(net.get("jitter_ratio", 0.3))
    packet_loss = float(net.get("packet_loss", 0.0))
    region_weights = {k: float(v) for k, v in net["regions"].items()}
    supernode_fraction = float(net.get("supernode_fraction", 0.05))
    supernode_up = str(net.get("supernode_bandwidth_up",
                               net.get("supernode_bandwidth", "1 Gbit")))
    supernode_down = str(net.get("supernode_bandwidth_down",
                                 net.get("supernode_bandwidth", "1 Gbit")))
    non_up = str(net.get("non_supernode_bandwidth_up", "25 Mbit"))
    non_down = str(net.get("non_supernode_bandwidth_down",
                           net.get("non_supernode_bandwidth", "50 Mbit")))
    if not 0.0 <= supernode_fraction <= 1.0:
        die(f"[network].supernode_fraction must be between 0 and 1, got "
            f"{supernode_fraction}")

    nodes = build_nodes(cfg)
    n = len(nodes)
    if n > 250:
        log(f"warning: {n} nodes → a full inter-host mesh of {n * (n - 1) // 2} edges; "
            "topology generation and Shadow start-up may be slow.")

    geo_rng = random.Random(seed)
    regions = weighted_assign(region_weights, n, geo_rng)
    supernode_count = assign_supernodes(nodes, supernode_fraction, geo_rng)
    hybrid_selection, hybrid_fraction = hybrid_settings(cfg["sim"])
    hybrid_subscribers = assign_hybrid_subscribers(
        nodes, mode_setting(cfg["sim"]), hybrid_selection, hybrid_fraction, seed)
    for node, region in zip(nodes, regions):
        node.region = region
        if node.is_supernode:
            node.bandwidth_up = supernode_up
            node.bandwidth_down = supernode_down
        else:
            node.bandwidth_up = non_up
            node.bandwidth_down = non_down

    gml_path = out_dir / "topology.gml"
    gml_path.write_text(generate_gml(nodes, jitter_ratio, packet_loss, geo_rng))
    (out_dir / "regions.json").write_text(
        json.dumps({node.name: node.region for node in nodes}, indent=2))
    (out_dir / "bandwidths.json").write_text(json.dumps({
        node.name: {"up": node.bandwidth_up, "down": node.bandwidth_down,
                    "supernode": node.is_supernode,
                    "rs_subnet_subscriber": node.is_rs_subnet_subscriber}
        for node in nodes
    }, indent=2))

    peer_list = write_peers_json(nodes, cfg, out_dir, ec_sim_bin, image)

    peer_rng = random.Random(seed + 1)
    peers = wire_peers(nodes, int(cfg["topology"].get("peers_per_node", DEFAULT_PEERS_PER_NODE)),
                       peer_rng)
    (out_dir / "shadow.yaml").write_text(
        generate_shadow_yaml(nodes, cfg, gml_path, peers, ec_sim_bin, peer_list))

    region_counts: dict[str, int] = {}
    for x in nodes:
        region_counts[x.region] = region_counts.get(x.region, 0) + 1
    log(f"  {n} hosts (builder={nodes[0].name}); {supernode_count} supernodes; "
        f"{len(hybrid_subscribers)} hybrid chunk subscribers; regions {region_counts}")
    return n, {
        "hybrid_selection": hybrid_selection,
        "hybrid_rs_subnet_fraction": hybrid_fraction,
        "rs_subnet_subscriber_count": len(hybrid_subscribers),
        "rs_subnet_subscribers": [node.name for node in hybrid_subscribers],
    }


def analyze_and_serve(out_dir: Path, overlays: list[Path], serve: bool,
                      append: bool = False) -> None:
    script = REPO_ROOT / "scripts" / "analyze.py"
    if not script.is_file():
        log("scripts/analyze.py not found — skipping analysis")
        return
    dirs = [out_dir, *overlays]
    cmd = ["uv", "run", "--group", "analyze", "python3", str(script)]
    if serve:
        cmd.append("--serve")
    if append:
        cmd.append("--append")
    cmd += [str(d) for d in dirs]
    log("writing CLI summary + Plotly HTML…")
    subprocess.run(cmd, cwd=str(REPO_ROOT), check=False)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run ec-sim under Shadow.")
    ap.add_argument("config", nargs="?", default="ecsim.toml",
                    help="path to the TOML config (default: ecsim.toml)")
    ap.add_argument("--dry-run", action="store_true",
                    help="generate shadow.yaml + topology.gml only; no build or run")
    ap.add_argument("--rebuild", action="store_true", help="force `docker build` first")
    ap.add_argument("--clean", action="store_true",
                    help="remove previous shadow.data/, runs-history.json, and summary.html")
    ap.add_argument("--summary-only", action="store_true",
                    help="skip generation/build/run; just summarize an existing run")
    ap.add_argument("--serve", "-s", action="store_true",
                    help="after the run, serve the interactive summary HTML "
                         "at http://0.0.0.0:4321 until Ctrl+C")
    ap.add_argument("--serve-only", action="store_true",
                    help="skip the simulation; rebuild HTML from history and serve")
    ap.add_argument("--overlay", action="append", default=[], metavar="DIR",
                    help="extra output dir to import into the run history "
                         "(repeatable; skipped if already recorded)")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.is_absolute():
        cfg_path = REPO_ROOT / cfg_path
    if not cfg_path.is_file():
        die(f"config not found: {cfg_path}")
    with cfg_path.open("rb") as f:
        cfg = tomllib.load(f)

    sim_cfg = cfg.get("sim", {})
    mode_setting(sim_cfg)
    hybrid_settings(sim_cfg)
    for profile in MESH_PROFILES:
        mesh_settings(sim_cfg, profile)
    gossip_tuning_settings(sim_cfg)

    out_dir = Path(cfg["output"]["dir"])
    if not out_dir.is_absolute():
        out_dir = REPO_ROOT / out_dir
    overlays = []
    for raw in args.overlay:
        p = Path(raw)
        overlays.append(p if p.is_absolute() else REPO_ROOT / p)

    if args.summary_only:
        summarize(out_dir)
        return

    if args.serve_only:
        analyze_and_serve(out_dir, overlays, serve=True)
        return

    runner = str(cfg.get("run", {}).get("runner", "docker")).lower()
    if runner == "local":
        runner = "native"
    if runner not in ("docker", "native"):
        die(f'[run].runner must be "docker" or "native", got "{runner}"')
    ec_sim_bin = EC_SIM_BIN_DOCKER if runner == "docker" else EC_SIM_BIN_NATIVE

    out_dir.mkdir(parents=True, exist_ok=True)

    if args.clean:
        shutil.rmtree(out_dir / "shadow.data", ignore_errors=True)
        log(f"cleaned {out_dir / 'shadow.data'}")
        for name in ("runs-history.json", "summary.html"):
            path = out_dir / name
            try:
                path.unlink()
                log(f"cleaned {path}")
            except FileNotFoundError:
                pass

    base_seed = int(cfg["sim"]["seed"])
    runs = max(1, int(cfg["sim"].get("runs", 1)))

    image = cfg["docker"]["image_name"] if runner == "docker" else None
    if not args.dry_run:
        if runner == "docker":
            shadow_image = cfg["docker"].get("shadow_image", "kamilsa/shadow-arm:tcpfix")
            if args.rebuild or cfg["docker"].get("rebuild") or not image_exists(image):
                docker_build(image, shadow_image)
            else:
                log(f"reusing existing image {image} (pass --rebuild to force a rebuild)")
        else:
            cargo_build_release()

    if runs > 1:
        log(f"running {runs} runs (seeds {base_seed}..{base_seed + runs - 1})")

    for run_index in range(runs):
        run_seed = base_seed + run_index
        if runs > 1:
            log(f"─── run {run_index + 1}/{runs}  (seed {run_seed}) ───")
        _, hybrid_meta = _generate_run(cfg, out_dir, run_seed, ec_sim_bin, image)
        log(f"  runner: {runner}  mode: {mode_setting(sim_cfg)}")

        if args.dry_run:
            log("dry run — generated shadow.yaml only, skipping Shadow.")
            continue

        shutil.rmtree(out_dir / "shadow.data", ignore_errors=True)
        if runner == "docker":
            docker_run_shadow(image, out_dir)
        else:
            native_run_shadow(out_dir)

        flood, lazy, factor = gossip_tuning_settings(sim_cfg)
        mesh_meta = {}
        for profile in MESH_PROFILES:
            mesh_n, mesh_low, mesh_high, mesh_outbound = mesh_settings(sim_cfg, profile)
            mesh_meta.update({
                f"{profile}_mesh_n": mesh_n,
                f"{profile}_mesh_n_low": mesh_low,
                f"{profile}_mesh_n_high": mesh_high,
                f"{profile}_mesh_outbound_min": mesh_outbound,
            })
        (out_dir / "run-meta.json").write_text(json.dumps(
            {"seed": run_seed, "run_index": run_index, "runs": runs,
             "mode": mode_setting(sim_cfg),
             "payload_size_kib": _positive_int(sim_cfg, "payload_size_kib",
                                               DEFAULT_PAYLOAD_SIZE_KIB),
             "warmup_secs": _nonneg_int(sim_cfg, "warmup_secs", DEFAULT_WARMUP_SECS),
             "observe_secs": _nonneg_int(sim_cfg, "observe_secs", DEFAULT_OBSERVE_SECS),
              "flood_publish": flood,
              "gossip_lazy": lazy,
              "gossip_factor": factor,
              **mesh_meta,
              **hybrid_meta},
            indent=2))
        summarize(out_dir)
        analyze_and_serve(out_dir, overlays, serve=False, append=True)

    if args.dry_run:
        return

    log("done. Results under:")
    log(f"  {out_dir}/shadow.data/hosts/<host>/ec-sim.1000.stdout")
    if args.serve:
        analyze_and_serve(out_dir, overlays, serve=True, append=False)
    else:
        log(f"Analyse with:  uv run --group analyze python {REPO_ROOT}/scripts/analyze.py {out_dir}")


if __name__ == "__main__":
    main()
