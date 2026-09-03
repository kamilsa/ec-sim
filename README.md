# ec-sim

Minimal Rust + rust-libp2p payload-propagation simulator that runs under
[Shadow](https://shadow.github.io/) (Docker or native). Same `uv run` launcher
UX as blobsim (`--rebuild`, `--clean`, `--dry-run`), without an execution layer,
blobs, slot ticker, or zk-attesters.

One homogeneous network, one protocol per run. Connections warm up, the builder
publishes a **single payload**, every node observes, then exits.

## Modes

| `--mode` / `[sim].mode` | Wire | Reconstruct |
|---|---|---|
| `gossipsub` | Topic `/ec/payload/1`, one full message | First full message |
| `rs-partial` | Topic `/ec/payload_chunks/1`, gossipsub 1.3 partials | Any 64 of 128 RS shards |
| `rs-subnets` | Topics `/ec/payload_column/{0..127}/1` | Any 64 of 128 RS shards |
| `rlnc` | Custom `/ec-sim/rlnc/1.0.0` push | Rank `N` (default 10) |

All four modes are implemented. Flip `[sim].mode` and rerun the same topology
to compare time-to-N% reach and bytes sent.

## Run

```text
uv run shadow-sim.py                 # build (if needed) + run with ecsim.toml
uv run shadow-sim.py --dry-run       # generate shadow.yaml / topology.gml only
uv run shadow-sim.py --rebuild       # force docker build first
uv run shadow-sim.py --clean         # wipe previous shadow.data/
uv run shadow-sim.py --serve         # run, then print a summary and serve Plotly HTML
uv run shadow-sim.py --serve-only --overlay other-output
```

Default config (`ecsim.toml`): **128 nodes**, **256 KiB** payload, node 0 is the
builder, EIP-7870 bandwidth (50 Mbit down / 25 Mbit up) with 5% 1 Gbit
supernodes, blobsim geo latency matrix.

Results: `<output.dir>/shadow.data/hosts/<host>/ec-sim.1000.stdout`.

Each node emits structured `EVENT kind=... t_ms=...` lines on Shadow's shared
realtime clock (`warmup_complete`, `payload_published`, `payload_received`,
`payload_reconstructed`, `bytes`, `run_end`).

`--serve` prints time-to-50/90/99% reconstruction, a bytes summary, and serves a
self-contained Plotly HTML at http://0.0.0.0:4321/summary.html. Pass extra output
directories with `--overlay` to color-compare modes.
