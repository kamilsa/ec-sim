#!/usr/bin/env python3
"""Parse ec-sim EVENT logs into a CLI summary and a self-contained Plotly HTML.

Usage:
  python scripts/analyze.py DIR [DIR ...]
  python scripts/analyze.py --serve DIR [DIR ...]
  python scripts/analyze.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EVENT_RE = re.compile(r"EVENT kind=(\S+) t_ms=(\d+)(.*)$")
_ANSI = re.compile(r"\x1b\[[0-9;]*[mK]")
KV_RE = re.compile(r"(\w+)=(\S+)")

SERVE_PORT = 4321
HTML_NAME = "summary.html"


def parse_event_line(line: str) -> dict | None:
    """Parse one `EVENT kind=... t_ms=... k=v ...` line into a dict, or None."""
    line = _ANSI.sub("", line).strip()
    match = EVENT_RE.search(line)
    if not match:
        return None
    kind, t_ms, rest = match.group(1), int(match.group(2)), match.group(3)
    event: dict = {"kind": kind, "t_ms": t_ms}
    for key, raw in KV_RE.findall(rest):
        if raw in ("true", "false"):
            event[key] = raw == "true"
        elif raw == "NA":
            event[key] = None
        else:
            try:
                event[key] = int(raw)
            except ValueError:
                try:
                    event[key] = float(raw)
                except ValueError:
                    event[key] = raw
    return event


def iter_host_logs(run_dir: Path) -> list[tuple[str, Path]]:
    hosts = run_dir / "shadow.data" / "hosts"
    if not hosts.is_dir():
        return []
    out: list[tuple[str, Path]] = []
    for host in sorted(hosts.iterdir()):
        if not host.is_dir():
            continue
        matches = sorted(host.glob("ec-sim.*.stdout"))
        if matches:
            out.append((host.name, matches[0]))
    return out


def load_mode(run_dir: Path) -> str:
    meta = run_dir / "run-meta.json"
    if meta.is_file():
        try:
            return str(json.loads(meta.read_text()).get("mode") or run_dir.name)
        except json.JSONDecodeError:
            pass
    return run_dir.name


def collect_run(run_dir: Path) -> dict:
    """Load one Shadow output directory into a summary dict."""
    hosts: dict[str, dict] = {}
    for name, path in iter_host_logs(run_dir):
        text = path.read_text(errors="replace")
        rec: dict = {
            "reconstructed_ms": None,
            "published_ms": None,
            "warmup_ms": None,
            "tx": None,
            "rx": None,
            "run_end_reconstructed": False,
        }
        for line in text.splitlines():
            ev = parse_event_line(line)
            if ev is None:
                continue
            kind = ev["kind"]
            if kind == "warmup_complete" and rec["warmup_ms"] is None:
                rec["warmup_ms"] = ev["t_ms"]
            elif kind == "payload_published" and rec["published_ms"] is None:
                rec["published_ms"] = ev["t_ms"]
            elif kind == "payload_reconstructed" and rec["reconstructed_ms"] is None:
                rec["reconstructed_ms"] = ev["t_ms"]
            elif kind == "bytes":
                rec["tx"] = ev.get("tx")
                rec["rx"] = ev.get("rx")
            elif kind == "run_end":
                rec["run_end_reconstructed"] = bool(ev.get("reconstructed", False))
        hosts[name] = rec

    published = [h["published_ms"] for h in hosts.values() if h["published_ms"] is not None]
    t0 = min(published) if published else None
    if t0 is None:
        warmups = [h["warmup_ms"] for h in hosts.values() if h["warmup_ms"] is not None]
        t0 = min(warmups) if warmups else 0

    delays: list[float] = []
    for rec in hosts.values():
        if rec["reconstructed_ms"] is not None:
            delays.append(max(0.0, rec["reconstructed_ms"] - t0))
    delays.sort()

    n = len(hosts)
    reconstructed = len(delays)

    def time_to(frac: float) -> float | None:
        need = int(n * frac + 0.999999)  # ceil, at least 1 when n>0
        if n == 0 or reconstructed < need:
            return None
        return delays[need - 1]

    txs = [h["tx"] for h in hosts.values() if isinstance(h["tx"], int)]
    rxs = [h["rx"] for h in hosts.values() if isinstance(h["rx"], int)]
    return {
        "dir": str(run_dir),
        "label": load_mode(run_dir),
        "n_hosts": n,
        "reconstructed": reconstructed,
        "t0_ms": t0,
        "delays_ms": delays,
        "t50_ms": time_to(0.50),
        "t90_ms": time_to(0.90),
        "t99_ms": time_to(0.99),
        "tx_sum": sum(txs) if txs else 0,
        "rx_sum": sum(rxs) if rxs else 0,
        "tx_mean": (sum(txs) / len(txs)) if txs else 0.0,
        "rx_mean": (sum(rxs) / len(rxs)) if rxs else 0.0,
        "hosts": hosts,
    }


def _fmt_ms(value: float | None) -> str:
    if value is None:
        return "NA"
    return f"{value:.0f} ms"


def print_summary(run: dict) -> None:
    n = run["n_hosts"]
    rec = run["reconstructed"]
    pct = (100.0 * rec / n) if n else 0.0
    print(f"── {run['label']}  ({run['dir']})")
    print(f"   hosts: {n}  reconstructed: {rec}/{n} ({pct:.1f}%)")
    print(f"   time-to-50%: {_fmt_ms(run['t50_ms'])}  "
          f"time-to-90%: {_fmt_ms(run['t90_ms'])}  "
          f"time-to-99%: {_fmt_ms(run['t99_ms'])}")
    print(f"   tx bytes: sum={run['tx_sum']}  mean={run['tx_mean']:.0f}  "
          f"rx bytes: sum={run['rx_sum']}  mean={run['rx_mean']:.0f}")


def cdf_points(delays: list[float], n_hosts: int) -> tuple[list[float], list[float]]:
    """Step CDF: fraction of all hosts reconstructed vs delay (ms)."""
    if n_hosts == 0:
        return [], []
    xs: list[float] = [0.0]
    ys: list[float] = [0.0]
    for i, delay in enumerate(delays, start=1):
        xs.append(delay)
        ys.append(i / n_hosts)
    return xs, ys


def write_html(runs: list[dict], out_path: Path) -> None:
    import pandas as pd
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    fig = make_subplots(
        rows=1,
        cols=2,
        subplot_titles=("Reconstruction CDF", "Bytes per node (mean)"),
    )
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b"]
    for i, run in enumerate(runs):
        color = colors[i % len(colors)]
        xs, ys = cdf_points(run["delays_ms"], run["n_hosts"])
        fig.add_trace(
            go.Scatter(
                x=xs,
                y=ys,
                mode="lines",
                name=run["label"],
                line=dict(color=color, shape="hv"),
                hovertemplate="%{x:.0f} ms → %{y:.1%}<extra>" + run["label"] + "</extra>",
            ),
            row=1,
            col=1,
        )
        fig.add_trace(
            go.Bar(
                x=[f"{run['label']} tx", f"{run['label']} rx"],
                y=[run["tx_mean"], run["rx_mean"]],
                name=run["label"],
                marker_color=color,
                showlegend=False,
                hovertemplate="%{y:.0f} bytes<extra>" + run["label"] + "</extra>",
            ),
            row=1,
            col=2,
        )

    fig.update_xaxes(title_text="ms after publish", row=1, col=1)
    fig.update_yaxes(title_text="fraction reconstructed", range=[0, 1], row=1, col=1)
    fig.update_yaxes(title_text="bytes", row=1, col=2)
    fig.update_layout(
        title="ec-sim payload propagation",
        template="plotly_white",
        legend_title_text="mode",
        height=480,
    )

    rows = []
    for run in runs:
        rows.append({
            "mode": run["label"],
            "hosts": run["n_hosts"],
            "reconstructed": run["reconstructed"],
            "t50_ms": run["t50_ms"],
            "t90_ms": run["t90_ms"],
            "t99_ms": run["t99_ms"],
            "tx_mean": run["tx_mean"],
            "rx_mean": run["rx_mean"],
        })
    table = pd.DataFrame(rows).to_html(index=False, na_rep="NA", float_format=lambda x: f"{x:.0f}")

    html = fig.to_html(include_plotlyjs=True, full_html=False)
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>ec-sim summary</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 24px; color: #111; }}
    table {{ border-collapse: collapse; margin-top: 16px; }}
    th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: right; }}
    th {{ background: #f4f4f4; }}
  </style>
</head>
<body>
  <h1>ec-sim payload propagation</h1>
  {html}
  {table}
</body>
</html>
"""
    out_path.write_text(page)
    print(f"wrote {out_path}")


def serve(html_path: Path, port: int = SERVE_PORT) -> None:
    directory = str(html_path.parent.resolve())

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

        def log_message(self, fmt: str, *args) -> None:
            sys.stderr.write("[analyze] " + (fmt % args) + "\n")

    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"serving {html_path.name} at http://0.0.0.0:{port}/{html_path.name}")
    print("press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()


FIXTURE_EVENTS = """
EVENT kind=warmup_complete t_ms=1000 connected=8 mesh=6 timed_out=false
EVENT kind=payload_published t_ms=1010 bytes=256 hash=aa
EVENT kind=payload_reconstructed t_ms=1010 bytes=256 hash=aa
EVENT kind=bytes t_ms=3000 tx=1000 rx=10
EVENT kind=run_end t_ms=3000 reconstructed=true
---
EVENT kind=warmup_complete t_ms=1000 connected=8 mesh=6 timed_out=false
EVENT kind=payload_reconstructed t_ms=1110 bytes=256 hash=aa
EVENT kind=bytes t_ms=3000 tx=200 rx=1200
EVENT kind=run_end t_ms=3000 reconstructed=true
---
EVENT kind=warmup_complete t_ms=1000 connected=8 mesh=6 timed_out=false
EVENT kind=payload_reconstructed t_ms=1210 bytes=256 hash=aa
EVENT kind=bytes t_ms=3000 tx=180 rx=1180
EVENT kind=run_end t_ms=3000 reconstructed=true
---
EVENT kind=warmup_complete t_ms=1000 connected=7 mesh=5 timed_out=false
EVENT kind=bytes t_ms=3000 tx=50 rx=40
EVENT kind=run_end t_ms=3000 reconstructed=false
"""


def _write_fixture(root: Path) -> Path:
    run = root / "fixture-run"
    hosts = run / "shadow.data" / "hosts"
    blocks = [b.strip() for b in FIXTURE_EVENTS.strip().split("---")]
    for i, block in enumerate(blocks):
        host = hosts / f"node{i:03d}"
        host.mkdir(parents=True, exist_ok=True)
        (host / "ec-sim.1000.stdout").write_text(block + "\n")
    (run / "run-meta.json").write_text(json.dumps({"mode": "gossipsub"}))
    return run


def self_test() -> None:
    line = "EVENT kind=payload_reconstructed t_ms=1234 bytes=262144 hash=abcd reconstructed=true"
    ev = parse_event_line(line)
    assert ev is not None, "parser missed a well-formed EVENT"
    assert ev["kind"] == "payload_reconstructed"
    assert ev["t_ms"] == 1234
    assert ev["bytes"] == 262144
    assert ev["hash"] == "abcd"
    assert ev["reconstructed"] is True
    assert parse_event_line("not an event") is None

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = _write_fixture(Path(tmp))
        summary = collect_run(run_dir)
        assert summary["n_hosts"] == 4
        assert summary["reconstructed"] == 3
        # t0 = 1010 (publish); delays 0, 100, 200 → 50% of 4 hosts needs 2 → 100 ms
        assert summary["t50_ms"] == 100
        assert summary["t90_ms"] is None  # 90% of 4 is 4 reconstructed, only 3 did
        assert summary["tx_sum"] == 1000 + 200 + 180 + 50
        html = run_dir / HTML_NAME
        write_html([summary], html)
        assert html.is_file() and html.stat().st_size > 1000
    print("self-test ok")


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize ec-sim EVENT logs.")
    ap.add_argument("dirs", nargs="*", type=Path, help="Shadow output directories")
    ap.add_argument("--serve", action="store_true", help=f"serve HTML on port {SERVE_PORT}")
    ap.add_argument("--port", type=int, default=SERVE_PORT)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.dirs:
        ap.error("at least one output directory is required")

    runs = []
    for path in args.dirs:
        if not path.is_dir():
            print(f"error: not a directory: {path}", file=sys.stderr)
            sys.exit(1)
        run = collect_run(path)
        print_summary(run)
        runs.append(run)

    html_path = args.dirs[0] / HTML_NAME
    write_html(runs, html_path)
    if args.serve:
        serve(html_path, args.port)


if __name__ == "__main__":
    main()
