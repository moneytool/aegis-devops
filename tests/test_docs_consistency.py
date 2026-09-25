"""Docs must agree with the data and the code they describe.

Every check here corresponds to drift that actually shipped: a benchmark chart
that outlived two corpus rebuilds, reference pages describing the old
escalate-on-untrusted default after it changed, and corpus diversity figures
from a previous corpus. None of it broke a test, so none of it was caught.
"""

import inspect
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_core import __version__
from aegis_core.interceptor import AegisInterceptor

ROOT = Path(__file__).resolve().parent.parent
BENCH = json.loads((ROOT / "results" / "benchmark.json").read_text())
STATS = json.loads((ROOT / "data" / "corpus" / "stats.json").read_text())
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]


def _metrics():
    """verifier name (without -replay) -> the three headline numbers."""
    out = {}
    for name, row in BENCH["verifiers"].items():
        m = row.get("metrics", row)
        out[name.removesuffix("-replay")] = {
            "over-block": m["over_block_rate"],
            "poison-susceptibility": m["poison_susceptibility"],
            "ps_unauth + pe_unauth": m["ps_unauthorized"] + m["pe_unauthorized"],
        }
    return out


def _tables(text):
    """Yield (header cells, rows of cells) for every markdown table starting '| verifier'."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("| verifier"):
            continue
        header = [c.strip() for c in line.strip("|").split("|")]
        rows = []
        for row in lines[i + 2:]:
            if not row.startswith("|"):
                break
            rows.append([c.strip() for c in row.strip("|").split("|")])
        yield header, rows


@pytest.mark.parametrize("doc", ["README.md", "docs/benchmark.md"])
def test_results_tables_match_benchmark_json(doc):
    truth = _metrics()
    checked = 0
    for header, rows in _tables((ROOT / doc).read_text()):
        for row in rows:
            name = re.sub(r"\*|\(.*?\)", "", row[0]).strip()
            if name not in truth:
                continue
            for col, want in truth[name].items():
                if col not in header:
                    continue
                got = float(row[header.index(col)].replace("*", ""))
                assert got == pytest.approx(want, abs=5e-4), (
                    f"{doc}: {name} {col} is {got}, results/benchmark.json says {want:.3f}"
                )
                checked += 1
    assert checked, f"{doc}: found no results table to check"


def test_benchmark_svg_is_regenerated_from_current_results(tmp_path):
    committed = (ROOT / "docs" / "benchmark.svg").read_text()
    script = (ROOT / "scripts" / "make_benchmark_svg.py").read_text()
    # run the generator against a scratch copy so the check never rewrites the repo
    (tmp_path / "results").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "results" / "benchmark.json").write_text(json.dumps(BENCH))
    (tmp_path / "scripts" / "make_benchmark_svg.py").write_text(script)
    subprocess.run([sys.executable, str(tmp_path / "scripts" / "make_benchmark_svg.py")],
                   check=True, capture_output=True)
    fresh = (tmp_path / "docs" / "benchmark.svg").read_text()
    assert fresh == committed, (
        "docs/benchmark.svg is stale: run venv/bin/python scripts/make_benchmark_svg.py"
    )


@pytest.mark.parametrize("key", ["n_distinct_structural", "n_distinct_patterns",
                                 "n_distinct_rule_text"])
def test_corpus_diversity_figures_match_stats(key):
    want = STATS[key]
    for doc in DOCS:
        for got in re.findall(rf"{key}\s*=\s*(\d+)", doc.read_text()):
            assert int(got) == want, f"{doc.name}: says {key} = {got}, stats.json says {want}"


def test_default_untrusted_policy_is_discard():
    default = inspect.signature(AegisInterceptor).parameters["on_untrusted_match"].default
    assert default == "discard"


# Phrases that describe escalate-on-untrusted as the default. Mentions of the
# opt-in flag, or of the clauses that genuinely fail closed (env-unresolved,
# unknown-target, a broken ledger chain, uncovered under --fail-closed), are fine.
STALE_DEFAULT_PHRASES = [
    r"integrity failures \**fail closed",
    r"fails closed to ESCALATE",
    r"fail closed like any other quarantine",
    r"because the interceptor fails closed",
]


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_docs_do_not_describe_escalate_as_the_default(doc):
    text = doc.read_text()
    for phrase in STALE_DEFAULT_PHRASES:
        assert not re.search(phrase, text, re.I), f"{doc.name}: stale wording /{phrase}/"


def test_changelog_has_an_entry_for_the_package_version():
    assert f"## [{__version__}]" in (ROOT / "CHANGELOG.md").read_text()
