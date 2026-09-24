#!/usr/bin/env python3
# ruff: noqa: E501 -- SVG element strings are long by nature; wrapping them
# makes the generated markup harder to follow than the long lines.
"""Regenerate docs/benchmark.svg from results/benchmark.json.

The chart is generated rather than hand-drawn so it cannot drift from the
numbers, which it previously did: the committed SVG outlived two corpus
rebuilds and a change of default before anyone noticed.

Usage:  venv/bin/python scripts/make_benchmark_svg.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# (key in benchmark.json, label, how to read it)
GROUPS = [
    ("over_block_rate", "over-block rate", lambda m: m["over_block_rate"]),
    ("poison_susceptibility", "poison-susceptibility", lambda m: m["poison_susceptibility"]),
    ("unauth_acted", "acted on an unauthorized rule", lambda m: m["ps_unauthorized"] + m["pe_unauthorized"]),
]
# verifier key -> (display label, colour). llm-heuristic is omitted: it is a
# deterministic stand-in, not a measured system, and opa's numbers match it.
SERIES = [
    ("aegis", "aegis", "#2f855a"),
    ("codex", "codex (gpt-6-astra)", "#3182ce"),
    ("claude-cli", "claude-cli (haiku)", "#63b3ed"),
    ("opa-signed", "opa-signed", "#d69e2e"),
    ("opa", "opa", "#dd6b20"),
    ("ollama", "ollama (mistral 7B)", "#c53030"),
]
W, H = 1000, 520
X0, X1, YTOP, YBASE = 150, 960, 110, 400


def main() -> int:
    data = json.loads((ROOT / "results" / "benchmark.json").read_text())
    vs = data["verifiers"]
    # rows may be suffixed -replay when served from cache
    def metrics(key: str):
        for cand in (key, f"{key}-replay"):
            if cand in vs:
                return vs[cand].get("metrics", vs[cand])
        return None

    present = [(k, lbl, col) for k, lbl, col in SERIES if metrics(k) is not None]
    meta = data.get("meta", {})
    out = [
        f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" '
        'font-family="Helvetica, Arial, sans-serif" role="img">',
        "<title>Aegis benchmark: over-block, poison-susceptibility, and unauthorized rules acted on</title>",
        f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
        f'<text x="{W/2}" y="30" text-anchor="middle" font-size="18" font-weight="700" '
        'fill="#1a202c">Benchmark — Aegis vs. baselines (lower is better)</text>',
        f'<text x="{W/2}" y="50" text-anchor="middle" font-size="11.5" fill="#718096">'
        f'holdout split, oracle: reference, n={meta.get("intents", 120)} intents, '
        f'n_distinct={meta.get("n_distinct_structural", 323)} of 500 constraints</text>',
        f'<line x1="{X0}" y1="{YBASE}" x2="{X1}" y2="{YBASE}" stroke="#2d3748" stroke-width="1.5"/>',
        f'<line x1="{X0}" y1="{YTOP}" x2="{X0}" y2="{YBASE}" stroke="#2d3748" stroke-width="1.5"/>',
    ]
    span = YBASE - YTOP
    for pct in (0, 25, 50, 75, 100):
        y = YBASE - span * pct / 100
        out.append(f'<text x="{X0-10}" y="{y+4}" text-anchor="end" font-size="10.5" fill="#4a5568">{pct}%</text>')
        if pct:
            out.append(f'<line x1="{X0}" y1="{y}" x2="{X1}" y2="{y}" stroke="#e2e8f0" stroke-width="1"/>')

    gw = (X1 - X0) / len(GROUPS)
    bw = gw * 0.78 / len(present)
    for gi, (_, glabel, read) in enumerate(GROUPS):
        gx = X0 + gi * gw
        out.append(f'<text x="{gx+gw/2}" y="{YBASE+26}" text-anchor="middle" font-size="12.5" '
                   f'font-weight="700" fill="#2d3748">{glabel}</text>')
        for si, (key, _, colour) in enumerate(present):
            v = max(0.0, min(1.0, float(read(metrics(key)))))
            bx = gx + gw * 0.11 + si * bw
            bh = span * v
            if bh < 1.5:  # keep a zero visible as a baseline tick
                out.append(f'<rect x="{bx:.1f}" y="{YBASE-2}" width="{bw*0.86:.1f}" height="2" fill="{colour}"/>')
            else:
                out.append(f'<rect x="{bx:.1f}" y="{YBASE-bh:.1f}" width="{bw*0.86:.1f}" '
                           f'height="{bh:.1f}" fill="{colour}"/>')
            out.append(f'<text x="{bx+bw*0.43:.1f}" y="{YBASE-bh-6:.1f}" text-anchor="middle" '
                       f'font-size="9.5" fill="#2d3748">{v:.2f}</text>')

    ly = YBASE + 58
    lx = X0
    for key, label, colour in present:
        out.append(f'<rect x="{lx}" y="{ly-9}" width="11" height="11" fill="{colour}"/>')
        out.append(f'<text x="{lx+16}" y="{ly}" font-size="11" fill="#4a5568">{label}</text>')
        lx += 22 + len(label) * 6.2
    out.append(f'<text x="{X0}" y="{ly+26}" font-size="10.5" fill="#718096">'
               'Rightmost group = ps_unauth + pe_unauth: the share of unauthorized-principal rules that moved a '
               'verdict at all.</text>')
    out.append(f'<text x="{X0}" y="{ly+42}" font-size="10.5" fill="#718096">'
               'codex and claude-cli are agent harnesses scored on a 100-constraint subset, not raw completions.</text>')
    out.append("</svg>")
    (ROOT / "docs" / "benchmark.svg").write_text("\n".join(out) + "\n")
    print(f"wrote docs/benchmark.svg ({len(present)} verifiers, {len(GROUPS)} groups)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
