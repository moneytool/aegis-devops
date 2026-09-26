#!/usr/bin/env python3
# ruff: noqa: E501 -- SVG element strings are long by nature.
"""Regenerate docs/latency.svg from results/latency.json.

Generated rather than hand-drawn so it cannot drift from the numbers
(tests/test_docs_consistency.py checks it is up to date).

Plots p95 and p99 decision latency against store size (log-log), with the
bootstrap 95% CI as whiskers. p50 is deliberately left out: the sweep sends
half its intents to rules that exist and half to nothing, and since a
decision is O(k) in the matching bucket a no-match costs almost nothing -- so
the median falls between two populations and describes neither.

Usage:  venv/bin/python scripts/make_latency_svg.py
"""
from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
W, H = 900, 520
X0, X1, YTOP, YBASE = 110, 860, 90, 400
SERIES = [("p95", "p95", "#3182ce"), ("p99", "p99 (with 95% CI)", "#c53030")]


def main() -> int:
    data = json.loads((ROOT / "results" / "latency.json").read_text())
    rows = sorted(data.get("results", data.get("sizes", data)), key=lambda r: r["size"])
    sizes = [r["size"] for r in rows]
    vals = [r["latency_ms"][k]["value"] for r in rows for k, _, _ in SERIES]
    lo_y = 10 ** math.floor(math.log10(min(vals)))
    hi_y = 10 ** math.ceil(math.log10(max(vals)))
    lx0, lx1 = math.log10(sizes[0]), math.log10(sizes[-1])

    def xp(s):
        return X0 + (math.log10(s) - lx0) / (lx1 - lx0) * (X1 - X0)

    def yp(v):
        return YBASE - (math.log10(max(v, lo_y)) - math.log10(lo_y)) / (math.log10(hi_y) - math.log10(lo_y)) * (YBASE - YTOP)

    out = [
        f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" font-family="Helvetica, Arial, sans-serif" role="img">',
        "<title>Aegis decision latency vs constraint-store size</title>",
        f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
        f'<text x="{W/2}" y="30" text-anchor="middle" font-size="18" font-weight="700" fill="#1a202c">Decision latency vs store size (log-log)</text>',
        f'<text x="{W/2}" y="50" text-anchor="middle" font-size="11.5" fill="#718096">results/latency.json — {rows[0].get("n_decisions", 2000)} warm decisions per size, full intercept()</text>',
        f'<line x1="{X0}" y1="{YBASE}" x2="{X1}" y2="{YBASE}" stroke="#2d3748" stroke-width="1.5"/>',
        f'<line x1="{X0}" y1="{YTOP}" x2="{X0}" y2="{YBASE}" stroke="#2d3748" stroke-width="1.5"/>',
    ]
    decade = lo_y
    while decade <= hi_y * 1.0001:
        y = yp(decade)
        out.append(f'<line x1="{X0}" y1="{y:.1f}" x2="{X1}" y2="{y:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        out.append(f'<text x="{X0-10}" y="{y+4:.1f}" text-anchor="end" font-size="10.5" fill="#4a5568">{decade:g} ms</text>')
        decade *= 10
    for s in sizes:
        out.append(f'<text x="{xp(s):.1f}" y="{YBASE+20}" text-anchor="middle" font-size="11" fill="#4a5568">{s:,}</text>')
    out.append(f'<text x="{(X0+X1)/2}" y="{YBASE+42}" text-anchor="middle" font-size="12" font-weight="700" fill="#2d3748">constraints in the store</text>')

    for key, _, colour in SERIES:
        pts = [(xp(r["size"]), yp(r["latency_ms"][key]["value"])) for r in rows]
        out.append('<polyline fill="none" stroke="{}" stroke-width="2.2" points="{}"/>'.format(
            colour, " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)))
        for r, (x, y) in zip(rows, pts):
            ci = r["latency_ms"][key].get("ci95")
            if key == "p99" and ci:
                y_lo, y_hi = yp(ci[0]), yp(ci[1])
                out.append(f'<line x1="{x:.1f}" y1="{y_lo:.1f}" x2="{x:.1f}" y2="{y_hi:.1f}" stroke="{colour}" stroke-width="1.4"/>')
                for yy in (y_lo, y_hi):
                    out.append(f'<line x1="{x-5:.1f}" y1="{yy:.1f}" x2="{x+5:.1f}" y2="{yy:.1f}" stroke="{colour}" stroke-width="1.4"/>')
            out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{colour}"/>')
            # p99 labels above the point, p95 below: the two lines run close together
            ty = y - 11 if key == "p99" else y + 17
            out.append(f'<text x="{x:.1f}" y="{ty:.1f}" text-anchor="middle" font-size="9.5" fill="{colour}">{r["latency_ms"][key]["value"]:.3f}</text>')

    ly = YBASE + 72
    lx = X0
    for _, label, colour in SERIES:
        out.append(f'<line x1="{lx}" y1="{ly-4}" x2="{lx+18}" y2="{ly-4}" stroke="{colour}" stroke-width="2.5"/>')
        out.append(f'<text x="{lx+24}" y="{ly}" font-size="11" fill="#4a5568">{label}</text>')
        lx += 170
    out.append(f'<text x="{X0}" y="{ly+22}" font-size="10.5" fill="#718096">p50 omitted: half the sweep\'s intents match no rule and cost almost nothing, so the median sits between two populations.</text>')
    out.append("</svg>")
    (ROOT / "docs" / "latency.svg").write_text("\n".join(out) + "\n")
    print(f"wrote docs/latency.svg ({len(rows)} sizes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
