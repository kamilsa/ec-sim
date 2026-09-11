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
| `gossipsub-rs` | Topic `/ec/payload_rs/1`, one message per RS shard | Any `data` of `total` RS shards |
| `rs-partial` | Topic `/ec/payload_chunks/1`, gossipsub 1.3 partials | Any 64 of 128 RS shards |
| `rs-subnets` | Topics `/ec/payload_column/{0..127}/1` | Any 64 of 128 RS shards |
| `chunk-subnets` | Topics `/ec/payload_chunk_subnet/{i}/1`, one raw chunk per subnet | All chunks, then SHA-256 verification |
| `hybrid` | Every node: `/ec/payload/1`; selected nodes: all 128 RS column topics | First full payload or any 64 shards; chunk reconstruction re-gossips the full payload |
| `rlnc` | Custom `/ec-sim/rlnc/1.0.0` push | Rank `N` (default 10) |

All eight modes are implemented. Flip `[sim].mode` and rerun the same topology
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
`/ec/payload_chunks/1`. `chunked_mesh_*` controls `/ec/payload_chunked/1`,
`chunk_subnet_mesh_*` controls every `/ec/payload_chunk_subnet/{i}/1` topic, and
`gossipsub_rs_mesh_*` controls `/ec/payload_rs/1`.
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

### Chunk Subnets

`chunk-subnets` sends the same raw chunks as `gossipsub-chunked`, but publishes
chunk `i` on its own topic `/ec/payload_chunk_subnet/{i}/1` — the per-chunk
topic split of `rs-subnets`, without the Reed-Solomon coding. It reuses
`[sim].gossipsub_chunk_count` (capped at 512, one gossipsub topic per chunk) and
`[sim].chunked_send_idontwant`, which sends `IDONTWANT` on that chunk's own
subnet mesh. Every node subscribes to every chunk subnet, because all chunks are
required to reconstruct.

Comparing `chunk-subnets` against `gossipsub-chunked` at the same chunk count
isolates the effect of per-chunk topic separation; comparing it against
`rs-subnets` isolates erasure coding. Note that `rs-subnets` can suppress all
128 shards the moment it decodes, while an all-of-N mode has nothing left to
suppress once it holds every chunk.

### Gossipsub RS

`gossipsub-rs` is `gossipsub-chunked` with erasure coding: the payload is
Reed-Solomon extended and every shard is published as an ordinary Gossipsub
message on the single topic `/ec/payload_rs/1`. A node reconstructs from any
`[sim].gossipsub_rs_data_shards` of `[sim].gossipsub_rs_total_shards`, then
regenerates the full shard set and sends one IDONTWANT per mesh peer covering
*every* shard id — including shards it never received.

The rate is the bandwidth dial. `total / data` is the wire multiplier: the
64-of-128 default puts 2x the payload on the mesh, while 64-of-80 costs 1.25x
and still tolerates 16 missing shards. `total_shards` may not exceed 256, the
GF(2^8) limit of the Reed-Solomon implementation.

This mode completes the 2x2: `gossipsub-chunked` (raw, one topic),
`chunk-subnets` (raw, topic per chunk), `gossipsub-rs` (coded, one topic), and
`rs-subnets` (coded, topic per shard). Holding the chunk count fixed, the row
comparison isolates topic separation and the column comparison isolates coding.
`[sim].chunked_send_idontwant` additionally enables per-shard IDONTWANT here.

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
