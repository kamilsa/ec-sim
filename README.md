# ec-sim

Minimal Rust + rust-libp2p payload-propagation simulator that runs under
[Shadow](https://shadow.github.io/) (Docker or native). Same `uv run` launcher
UX as blobsim (`--rebuild`, `--clean`, `--dry-run`), without an execution layer,
blobs, slot ticker, or zk-attesters.

One propagation mode per run. Connections warm up, the builder publishes a
**single payload**, every node observes, then exits. Hybrid mode assigns a
subset of nodes an additional chunk-subscriber role.

## Modes

| `--mode` / `[sim].mode` | Wire | Reconstruct |
|---|---|---|
| `gossipsub` | Topic `/ec/payload/1`, one full message | First full message |
| `gossipsub-chunked` | Topic `/ec/payload_chunked/1`, configurable raw chunks (default 64) | All chunks, then SHA-256 verification |
| `rs-partial` | Topic `/ec/payload_chunks/1`, gossipsub 1.3 partials | Any 64 of 128 RS shards |
| `rs-subnets` | Topics `/ec/payload_column/{0..127}/1` | Any 64 of 128 RS shards |
| `hybrid` | Every node: `/ec/payload/1`; selected nodes: all 128 RS column topics | First full payload or any 64 shards; chunk reconstruction re-gossips the full payload |
| `rlnc` | Custom `/ec-sim/rlnc/1.0.0` push | Rank `N` (default 10) |

All six modes are implemented. Flip `[sim].mode` and rerun the same topology
to compare time-to-N% reach and bytes sent.

### Hybrid roles

Set `[sim].hybrid_selection` to `fraction` to select a deterministic random
portion of nodes via `[sim].hybrid_rs_subnet_fraction`, or `supernodes` to
select every generated supernode. The builder is always included so it can
seed the subnet meshes with shards. The selected fraction and the supernode
selection must produce at least two chunk subscribers.

The builder publishes both the full payload and all RS shards. A hybrid node
that reconstructs from 64 shards publishes the recovered payload on
`/ec/payload/1` and emits `payload_bridged`. Since ordinary payload gossip can
reconstruct every node independently, use `shard_received`, `payload_bridged`,
and the per-node role recorded in `bandwidths.json` to evaluate the chunk path.

### Topic Mesh Degrees

Configure each gossipsub topic class independently with the four `D` values:
`execution_mesh_*` controls `/ec/payload/1`, `subnet_mesh_*` controls every
`/ec/payload_column/{0..127}/1` topic, and `partial_mesh_*` controls
`/ec/payload_chunks/1`. `chunked_mesh_*` controls `/ec/payload_chunked/1`.
Each profile supplies `_n`, `_n_low`, `_n_high`, and `_outbound_min`, and must
satisfy `outbound_min <= n_low <= n <= n_high` plus `2 * outbound_min <= n`.
The old generic `mesh_*` settings are rejected.

### Chunked Gossipsub

`gossipsub-chunked` sends the origin payload as contiguous normal-Gossipsub
messages on `/ec/payload_chunked/1`. Set `[sim].gossipsub_chunk_count` to
choose the number of chunks (default 64); when the payload is smaller than the
requested count, it uses one non-empty chunk per payload byte. Every receiver
needs all chunks and verifies the final SHA-256 commitment before reporting
reconstruction. `[sim].chunked_gossip_lazy` configures its `D_lazy`; the global
`gossip_factor` remains applicable to all Gossipsub modes. Set
`[sim].chunked_send_idontwant = true` to send `IDONTWANT` to mesh peers after
each newly accepted chunk.

## Run

```text
uv run shadow-sim.py                 # build (if needed) + run with ecsim.toml
uv run shadow-sim.py --dry-run       # generate shadow.yaml / topology.gml only
uv run shadow-sim.py --rebuild       # force docker build first
uv run shadow-sim.py --clean         # wipe shadow.data/, run history, and summary.html
uv run shadow-sim.py --serve         # run, snapshot history, serve interactive HTML
uv run shadow-sim.py --serve-only --overlay other-output
```

Default config (`ecsim.toml`): **128 nodes**, **256 KiB** payload, node 0 is the
builder, EIP-7870 bandwidth (50 Mbit down / 25 Mbit up) with 5% 1 Gbit
supernodes, blobsim geo latency matrix.

Results: `<output.dir>/shadow.data/hosts/<host>/ec-sim.1000.stdout`.

Each node emits structured `EVENT kind=... t_ms=...` lines on Shadow's shared
realtime clock (`warmup_complete`, `payload_published`, `payload_received`,
`payload_reconstructed`, `bytes`, `run_end`).

Every successful run is appended to `<output.dir>/runs-history.json` and the
self-contained `summary.html` is rewritten from that history. Click a table row
to select a run and see its reconstruction CDF, per-node sent and received byte
distributions, and a selectable node's sent and received bytes. Supernode bars
use a distinct color, and distribution titles include mean and median bytes.
`--clean` wipes the history table so a new campaign starts empty. `--overlay DIR`
imports extra output dirs into the same history (skipped if that dir + seed +
`run_index` is already recorded).

`--serve` prints time-to-50/95/99% reconstruction, a bytes summary, and serves
the page at http://0.0.0.0:4321/summary.html. `--serve-only` rebuilds HTML from
existing history without duplicating the current dir.
