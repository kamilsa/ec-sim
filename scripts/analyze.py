#!/usr/bin/env python3
"""Parse ec-sim EVENT logs into a CLI summary and a self-contained Plotly HTML.

Usage:
  python scripts/analyze.py [--serve] [--append] [--port N] DIR [DIR ...]
  python scripts/analyze.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from html import escape
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EVENT_RE = re.compile(r"EVENT kind=(\S+) t_ms=(\d+)(.*)$")
_ANSI = re.compile(r"\x1b\[[0-9;]*[mK]")
KV_RE = re.compile(r"(\w+)=(\S+)")

SERVE_PORT = 4321
HTML_NAME = "summary.html"
HISTORY_NAME = "runs-history.json"


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


def load_run_meta(run_dir: Path) -> dict:
    meta = run_dir / "run-meta.json"
    if meta.is_file():
        try:
            data = json.loads(meta.read_text())
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    return {}


def load_mode(run_dir: Path) -> str:
    return str(load_run_meta(run_dir).get("mode") or run_dir.name)


def collect_run(run_dir: Path) -> dict:
    """Load one Shadow output directory into a summary dict."""
    hosts: dict[str, dict] = {}
    for name, path in iter_host_logs(run_dir):
        text = path.read_text(errors="replace")
        rec: dict = {
            "reconstructed_ms": None,
            "published_ms": None,
            "warmup_ms": None,
            "sent": None,
            "rcvd": None,
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
                rec["sent"] = ev.get("tx")
                rec["rcvd"] = ev.get("rx")
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

    sents = [h["sent"] for h in hosts.values() if isinstance(h["sent"], int)]
    rcvds = [h["rcvd"] for h in hosts.values() if isinstance(h["rcvd"], int)]
    meta = load_run_meta(run_dir)
    return {
        "dir": str(run_dir.resolve()),
        "label": str(meta.get("mode") or run_dir.name),
        "seed": meta.get("seed"),
        "run_index": meta.get("run_index"),
        "n_hosts": n,
        "reconstructed": reconstructed,
        "t0_ms": t0,
        "delays_ms": delays,
        "t50_ms": time_to(0.50),
        "t95_ms": time_to(0.95),
        "t99_ms": time_to(0.99),
        "sent_sum": sum(sents) if sents else 0,
        "rcvd_sum": sum(rcvds) if rcvds else 0,
        "sent_mean": (sum(sents) / len(sents)) if sents else 0.0,
        "rcvd_mean": (sum(rcvds) / len(rcvds)) if rcvds else 0.0,
        "hosts": hosts,
    }


def history_path(out_dir: Path) -> Path:
    return out_dir / HISTORY_NAME


def load_history(out_dir: Path) -> list[dict]:
    path = history_path(out_dir)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [normalize_snapshot(row) for row in data if isinstance(row, dict)]


def save_history(out_dir: Path, history: list[dict]) -> None:
    history_path(out_dir).write_text(json.dumps(history, indent=2) + "\n")


def clean_history(out_dir: Path) -> None:
    for name in (HISTORY_NAME, HTML_NAME):
        path = out_dir / name
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _byte_value(rec: dict, *keys: str):
    for key in keys:
        if key in rec and rec[key] is not None:
            return rec[key]
    return None


def normalize_snapshot(snap: dict) -> dict:
    """Map legacy tx/rx snapshot fields onto sent/rcvd."""
    hosts = {}
    for name, rec in (snap.get("hosts") or {}).items():
        if not isinstance(rec, dict):
            continue
        hosts[name] = {
            "sent": _byte_value(rec, "sent", "tx"),
            "rcvd": _byte_value(rec, "rcvd", "rx"),
            "reconstructed_ms": rec.get("reconstructed_ms"),
        }
    out = dict(snap)
    out["sent_mean"] = snap.get("sent_mean", snap.get("tx_mean", 0.0))
    out["rcvd_mean"] = snap.get("rcvd_mean", snap.get("rx_mean", 0.0))
    out["hosts"] = hosts
    return out


def snapshot_identity(snap: dict) -> tuple:
    return (str(Path(snap["dir"]).resolve()), snap.get("seed"), snap.get("run_index"))


def already_in_history(history: list[dict], snap: dict) -> bool:
    key = snapshot_identity(snap)
    return any(snapshot_identity(row) == key for row in history)


def make_snapshot(run: dict, recorded_at: str | None = None) -> dict:
    if recorded_at is None:
        recorded_at = datetime.now(timezone.utc).isoformat()
    ts = recorded_at.replace("+00:00", "Z")
    label = run["label"]
    seed = run.get("seed")
    run_index = run.get("run_index")
    hosts = {}
    for name, rec in run.get("hosts", {}).items():
        hosts[name] = {
            "sent": _byte_value(rec, "sent", "tx"),
            "rcvd": _byte_value(rec, "rcvd", "rx"),
            "reconstructed_ms": rec.get("reconstructed_ms"),
        }
    return {
        "id": f"{ts}_{label}_{seed}_{run_index}",
        "recorded_at": recorded_at,
        "dir": str(Path(run["dir"]).resolve()),
        "label": label,
        "seed": seed,
        "run_index": run_index,
        "n_hosts": run["n_hosts"],
        "reconstructed": run["reconstructed"],
        "t50_ms": run["t50_ms"],
        "t95_ms": run.get("t95_ms"),
        "t99_ms": run["t99_ms"],
        "sent_mean": run.get("sent_mean", run.get("tx_mean", 0.0)),
        "rcvd_mean": run.get("rcvd_mean", run.get("rx_mean", 0.0)),
        "delays_ms": list(run.get("delays_ms") or []),
        "hosts": hosts,
    }


def snapshot_from_dir(run_dir: Path, *, verbose: bool = True) -> dict:
    run = collect_run(run_dir)
    if verbose:
        print_summary(run)
    return make_snapshot(run)


def update_history(primary: Path, extras: list[Path], append: bool,
                   *, verbose: bool = True) -> list[dict]:
    history = load_history(primary)
    if append:
        history.append(snapshot_from_dir(primary, verbose=verbose))
        for extra in extras:
            snap = snapshot_from_dir(extra, verbose=verbose)
            if not already_in_history(history, snap):
                history.append(snap)
    elif not history:
        for path in [primary, *extras]:
            snap = snapshot_from_dir(path, verbose=verbose)
            if not already_in_history(history, snap):
                history.append(snap)
    else:
        for extra in extras:
            snap = snapshot_from_dir(extra, verbose=verbose)
            if not already_in_history(history, snap):
                history.append(snap)
    save_history(primary, history)
    return history


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
          f"time-to-95%: {_fmt_ms(run['t95_ms'])}  "
          f"time-to-99%: {_fmt_ms(run['t99_ms'])}")
    print(f"   sent bytes: sum={run['sent_sum']}  mean={run['sent_mean']:.0f}  "
          f"rcvd bytes: sum={run['rcvd_sum']}  mean={run['rcvd_mean']:.0f}")


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


def _fmt_cell(value) -> str:
    if value is None or value == "":
        return "NA"
    if isinstance(value, float):
        return f"{value:.0f}"
    return str(value)


def _fmt_time(value) -> str:
    if not value:
        return "NA"
    text = str(value).replace("T", " ")
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


def write_html(runs: list[dict], out_path: Path) -> None:
    from plotly.offline import get_plotlyjs

    columns = [
        ("time", "time", True),
        ("seed", "seed", False),
        ("mode", "mode", True),
        ("hosts", "hosts", False),
        ("reconstructed", "reconstructed", False),
        ("t50_ms", "t50_ms", False),
        ("t95_ms", "t95_ms", False),
        ("t99_ms", "t99_ms", False),
        ("sent_mean", "sent_mean", False),
        ("rcvd_mean", "rcvd_mean", False),
    ]
    last = len(runs) - 1
    body_rows = []
    for i, run in enumerate(runs):
        values = {
            "time": _fmt_time(run.get("recorded_at")),
            "seed": _fmt_cell(run.get("seed")),
            "mode": run.get("label") or "NA",
            "hosts": _fmt_cell(run.get("n_hosts")),
            "reconstructed": _fmt_cell(run.get("reconstructed")),
            "t50_ms": _fmt_cell(run.get("t50_ms")),
            "t95_ms": _fmt_cell(run.get("t95_ms")),
            "t99_ms": _fmt_cell(run.get("t99_ms")),
            "sent_mean": _fmt_cell(run.get("sent_mean", run.get("tx_mean"))),
            "rcvd_mean": _fmt_cell(run.get("rcvd_mean", run.get("rx_mean"))),
        }
        selected = " selected" if i == last else ""
        cells = []
        for key, _label, textual in columns:
            cls = ' class="text"' if textual else ""
            cells.append(f"<td{cls}>{escape(values[key])}</td>")
        body_rows.append(
            f'<tr class="run-row{selected}" data-idx="{i}" tabindex="0">'
            + "".join(cells)
            + "</tr>"
        )
    thead_cells = []
    for _key, label, textual in columns:
        cls = ' class="text"' if textual else ""
        thead_cells.append(f"<th{cls}>{escape(label)}</th>")
    thead = "".join(thead_cells)
    tbody = "\n        ".join(body_rows)
    table = f"""<table id="runs">
      <thead><tr>{thead}</tr></thead>
      <tbody>
        {tbody}
      </tbody>
    </table>"""

    runs_json = json.dumps(runs).replace("<", "\\u003c")
    page = (
        _HTML_PAGE.replace("__TABLE__", table)
        .replace("__RUNS_JSON__", runs_json)
        .replace("__PLOTLY_JS__", get_plotlyjs())
    )
    out_path.write_text(page)
    print(f"wrote {out_path}")


_HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>ec-sim summary</title>
  <style>
    :root {
      --paper: #eef3f1;
      --ink: #1b2a32;
      --muted: #5b6b73;
      --rule: #c9d4d0;
      --selected: #d7ebe3;
      --stripe: #2a6f62;
      --hover: #e4eeea;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 28px 32px 48px;
      background: var(--paper);
      color: var(--ink);
      font-family: "Trebuchet MS", "Segoe UI", sans-serif;
    }
    h1 {
      font-size: 1.6rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      margin: 0 0 6px;
    }
    .lede {
      color: var(--muted);
      margin: 0 0 20px;
      font-size: 0.95rem;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      margin: 0 0 24px;
      font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace;
      font-size: 0.82rem;
    }
    th, td {
      border-bottom: 1px solid var(--rule);
      padding: 8px 10px;
      text-align: right;
      white-space: nowrap;
    }
    th {
      color: var(--muted);
      font-weight: 600;
      text-transform: lowercase;
      letter-spacing: 0.02em;
    }
    th.text, td.text { text-align: left; }
    .run-row { cursor: pointer; }
    .run-row:hover { background: var(--hover); }
    .run-row.selected {
      background: var(--selected);
      box-shadow: inset 4px 0 0 var(--stripe);
    }
    .run-row:focus-visible {
      outline: 2px solid var(--stripe);
      outline-offset: -2px;
    }
    .charts {
      display: grid;
      grid-template-columns: 1.4fr 1fr;
      gap: 24px;
      align-items: start;
    }
    #cdf, #bytes { width: 100%; min-height: 360px; }
    .bytes-panel label {
      display: block;
      color: var(--muted);
      font-size: 0.85rem;
      margin-bottom: 6px;
    }
    #node-select {
      font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace;
      font-size: 0.85rem;
      color: var(--ink);
      background: #f7faf8;
      border: 1px solid var(--rule);
      padding: 6px 8px;
      margin-bottom: 8px;
      max-width: 100%;
    }
    @media (max-width: 900px) {
      .charts { grid-template-columns: 1fr; }
    }
    @media (prefers-reduced-motion: reduce) {
      .run-row { transition: none; }
    }
  </style>
</head>
<body>
  <h1>ec-sim payload propagation</h1>
  <p class="lede">Click a run to inspect its reconstruction CDF. Pick a node to see that node's sent and received bytes.</p>
  __TABLE__
  <div class="charts">
    <div id="cdf"></div>
    <div class="bytes-panel">
      <label for="node-select">Node</label>
      <select id="node-select"></select>
      <div id="bytes"></div>
    </div>
  </div>
  <script>const RUNS = __RUNS_JSON__;</script>
  <script>__PLOTLY_JS__</script>
  <script>
    var selectedIdx = RUNS.length ? RUNS.length - 1 : -1;
    var plotCfg = {responsive: true, displaylogo: false};
    var plotBase = {
      margin: {t: 48, r: 24, b: 48, l: 56},
      height: 360,
      paper_bgcolor: "#eef3f1",
      plot_bgcolor: "#f7faf8",
      font: {color: "#1b2a32", family: "Trebuchet MS, Segoe UI, sans-serif"}
    };
    function cdfPoints(delays, nHosts) {
      if (!nHosts) return {x: [], y: []};
      var x = [0], y = [0];
      for (var i = 0; i < delays.length; i++) {
        x.push(delays[i]);
        y.push((i + 1) / nHosts);
      }
      return {x: x, y: y};
    }
    function nodeNames(run) {
      return Object.keys((run && run.hosts) || {}).sort();
    }
    function renderCdf(idx) {
      if (!RUNS.length) return;
      var run = RUNS[idx];
      var pts = cdfPoints(run.delays_ms || [], run.n_hosts || 0);
      var data = [{
        x: pts.x,
        y: pts.y,
        type: "scatter",
        mode: "lines",
        line: {shape: "hv", color: "#2a6f62", width: 2},
        hovertemplate: "%{x:.0f} ms → %{y:.1%}<extra></extra>",
        name: run.label || ""
      }];
      var layout = Object.assign({}, plotBase, {
        title: {text: "Reconstruction CDF", font: {size: 16}},
        xaxis: {title: "ms after publish", gridcolor: "#c9d4d0", zeroline: false},
        yaxis: {title: "fraction reconstructed", range: [0, 1], gridcolor: "#c9d4d0", zeroline: false},
        showlegend: false
      });
      var el = document.getElementById("cdf");
      if (el && el.data) Plotly.react(el, data, layout, plotCfg);
      else Plotly.newPlot("cdf", data, layout, plotCfg);
    }
    function renderBytes(run, name) {
      var rec = (name && run.hosts && run.hosts[name]) || {};
      var sent = typeof rec.sent === "number" ? rec.sent
                 : (typeof rec.tx === "number" ? rec.tx : 0);
      var rcvd = typeof rec.rcvd === "number" ? rec.rcvd
                 : (typeof rec.rx === "number" ? rec.rx : 0);
      var data = [{
        x: ["sent", "rcvd"],
        y: [sent, rcvd],
        type: "bar",
        marker: {color: ["#2a6f62", "#b56a3a"]},
        hovertemplate: "%{y:.0f} bytes<extra></extra>"
      }];
      var layout = Object.assign({}, plotBase, {
        title: {text: name ? ("Bytes · " + name) : "Bytes", font: {size: 16}},
        yaxis: {title: "bytes", gridcolor: "#c9d4d0", zeroline: false},
        xaxis: {title: ""},
        showlegend: false
      });
      var el = document.getElementById("bytes");
      if (el && el.data) Plotly.react(el, data, layout, plotCfg);
      else Plotly.newPlot("bytes", data, layout, plotCfg);
    }
    function fillNodes(run) {
      var sel = document.getElementById("node-select");
      var names = nodeNames(run);
      sel.innerHTML = "";
      for (var i = 0; i < names.length; i++) {
        var opt = document.createElement("option");
        opt.value = names[i];
        opt.textContent = names[i];
        sel.appendChild(opt);
      }
      var first = names.length ? names[0] : "";
      sel.value = first;
      renderBytes(run, first);
    }
    function selectRun(idx) {
      selectedIdx = idx;
      document.querySelectorAll(".run-row").forEach(function(row) {
        row.classList.toggle("selected", Number(row.getAttribute("data-idx")) === idx);
      });
      renderCdf(idx);
      fillNodes(RUNS[idx]);
    }
    document.querySelectorAll(".run-row").forEach(function(row) {
      row.addEventListener("click", function() {
        selectRun(Number(row.getAttribute("data-idx")));
      });
      row.addEventListener("keydown", function(ev) {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          selectRun(Number(row.getAttribute("data-idx")));
        }
      });
    });
    document.getElementById("node-select").addEventListener("change", function() {
      if (selectedIdx < 0) return;
      renderBytes(RUNS[selectedIdx], this.value);
    });
    if (RUNS.length) selectRun(RUNS.length - 1);
  </script>
</body>
</html>
"""


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
    (run / "run-meta.json").write_text(json.dumps({
        "mode": "gossipsub",
        "seed": 42,
        "run_index": 0,
    }))
    return run


def _assert_interactive_js_parses(html: str) -> None:
    """The last <script> is our click handlers; it must be valid JavaScript."""
    start = html.rfind("<script>")
    end = html.rfind("</script>")
    assert start != -1 and end > start, "missing interactive script"
    js = html[start + len("<script>"):end]
    assert "function selectRun" in js
    import shutil
    import subprocess
    import tempfile
    node = shutil.which("node")
    if node is None:
        return
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
        fh.write(js)
        path = fh.name
    try:
        subprocess.run([node, "--check", path], check=True, capture_output=True, text=True)
    finally:
        Path(path).unlink(missing_ok=True)


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
        assert summary["t95_ms"] is None  # 95% of 4 is 4 reconstructed, only 3 did
        assert summary["sent_sum"] == 1000 + 200 + 180 + 50
        assert summary["rcvd_sum"] == 10 + 1200 + 1180 + 40
        assert summary["seed"] == 42
        assert summary["run_index"] == 0
        html = run_dir / HTML_NAME
        write_html([summary], html)
        assert html.is_file() and html.stat().st_size > 1000

        hist = update_history(run_dir, [], append=True, verbose=False)
        assert len(hist) == 1
        assert hist[0]["seed"] == 42
        assert hist[0]["run_index"] == 0
        assert hist[0]["t95_ms"] is None
        assert "node000" in hist[0]["hosts"]
        hist = update_history(run_dir, [], append=True, verbose=False)
        assert len(hist) == 2
        write_html(hist, html)
        text = html.read_text()
        marker = "const RUNS = "
        start = text.index(marker) + len(marker)
        end = text.index(";</script>", start)
        embedded = json.loads(text[start:end])
        assert len(embedded) == 2
        assert "data-idx" in text
        assert 'id="cdf"' in text
        assert 'id="node-select"' in text
        assert ">t95_ms<" in text
        assert ">sent_mean<" in text
        assert ">rcvd_mean<" in text
        assert 'x: ["sent", "rcvd"]' in text
        assert "Plotly" in text
        assert "node000" in text
        assert "node003" in text
        assert 'value="" +' not in text
        assert "createElement" in text
        _assert_interactive_js_parses(text)

        hist = update_history(run_dir, [], append=False, verbose=False)
        assert len(hist) == 2
        hist = update_history(run_dir, [run_dir], append=False, verbose=False)
        assert len(hist) == 2

        other_dir = _write_fixture(Path(tmp) / "overlay")
        hist = update_history(run_dir, [other_dir], append=False, verbose=False)
        assert len(hist) == 3
        hist = update_history(run_dir, [other_dir], append=False, verbose=False)
        assert len(hist) == 3
        assert (run_dir / HISTORY_NAME).is_file()

        write_html([], html)
        empty_text = html.read_text()
        assert "const RUNS = []" in empty_text

        write_html(hist, html)
        clean_history(run_dir)
        assert not (run_dir / HISTORY_NAME).exists()
        assert not html.exists()
    print("self-test ok")


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize ec-sim EVENT logs.")
    ap.add_argument("dirs", nargs="*", type=Path, help="Shadow output directories")
    ap.add_argument("--serve", action="store_true", help=f"serve HTML on port {SERVE_PORT}")
    ap.add_argument("--append", action="store_true",
                    help="always snapshot the first dir as a new history row")
    ap.add_argument("--port", type=int, default=SERVE_PORT)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.dirs:
        ap.error("at least one output directory is required")

    for path in args.dirs:
        if not path.is_dir():
            print(f"error: not a directory: {path}", file=sys.stderr)
            sys.exit(1)

    primary = args.dirs[0]
    extras = args.dirs[1:]
    history = update_history(primary, extras, append=args.append)
    html_path = primary / HTML_NAME
    write_html(history, html_path)
    if args.serve:
        serve(html_path, args.port)


if __name__ == "__main__":
    main()
