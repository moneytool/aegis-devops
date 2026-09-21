"""Baseline verifiers compared against Aegis in the Week 7-8 benchmark
(PLAN.md §4).

Every verifier here implements the same tiny protocol (see ``base.py``) so
``scripts/benchmark.py`` can run Aegis and the baselines through one loop
and produce a single confusion matrix / latency table.
"""

from aegis_core.baselines.base import AegisVerifier, Verifier

__all__ = ["Verifier", "AegisVerifier"]
