"""Turning token counts into estimated dollars (design v1.0, §5).

Usage is stored as tokens per billing category under the model id the log
recorded; dollars are computed here, when read, from the built-in table
(``prices.yaml``) and the signed overrides in ``budget.yaml``. Adding an
override therefore re-prices earlier usage without re-reading any log.

A price is **explicit** when an override or a table entry gives it. Any
other price is a fallback and only an estimate: per category, the highest
rate among the model's vendor's entries, or across the whole table when the
vendor cannot be identified. A new model can cost more than every model the
table knows, so the fallback is not an upper bound.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

import yaml

CATEGORIES = ("input", "output", "cache_read", "cache_write")
PER_TOKENS = 1_000_000

# Log provider fields that name one vendor. Others (github-copilot, openrouter,
# ...) route to many vendors, so the model id's prefix decides instead.
_PROVIDER_VENDOR = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google",
    "gemini": "google",
    "google-vertex": "google",
}
_DATE_SUFFIX = re.compile(r"-(?:\d{8}|\d{4}-\d{2}-\d{2})$")
_BRACKET_SUFFIX = re.compile(r"\[[^\]]*\]$")


def normalize_model(model: str) -> str:
    """The key a model id is matched on: lower case, without a provider
    prefix (``anthropic/``), a context-size tag (``[1m]``) or a date suffix,
    with dots read as dashes (``claude-sonnet-4.5`` is ``claude-sonnet-4-5``)."""
    m = model.strip().lower()
    m = m.rsplit("/", 1)[-1]
    m = _BRACKET_SUFFIX.sub("", m)
    m = _DATE_SUFFIX.sub("", m)
    return m.replace(".", "-")


@dataclass(frozen=True)
class Price:
    """What one model costs, per category (USD per million tokens). A
    category in ``estimated`` came from a fallback, not a published price."""

    model: str
    vendor: str | None
    rates: Mapping[str, float]
    estimated: frozenset[str] = frozenset()

    def cost(self, usage: Mapping[str, int]) -> float:
        return sum(usage.get(c, 0) * self.rates[c] for c in CATEGORIES) / PER_TOKENS


@dataclass
class Cost:
    """Dollars for a set of usage, and which models were (partly) estimated."""

    dollars: float = 0.0
    estimated: dict[str, list[str]] = field(default_factory=dict)  # model -> categories

    def add(self, other: Cost) -> None:
        self.dollars += other.dollars
        for model, cats in other.estimated.items():
            merged = sorted(set(self.estimated.get(model, [])) | set(cats))
            self.estimated[model] = merged


def _check_rates(where: str, entry: Any, *, require_all: bool) -> dict[str, float]:
    if not isinstance(entry, dict):
        raise ValueError(f"{where}: must be a mapping of {', '.join(CATEGORIES)}")
    unknown = set(entry) - set(CATEGORIES)
    if unknown:
        raise ValueError(f"{where}: unknown price field(s) {sorted(unknown)}")
    missing = [c for c in CATEGORIES if c not in entry]
    if require_all and missing:
        raise ValueError(f"{where}: missing price field(s) {missing}")
    rates: dict[str, float] = {}
    for cat, value in entry.items():
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value < 0):
            raise ValueError(f"{where}.{cat}: must be a finite number >= 0 "
                             "(USD per million tokens)")
        rates[cat] = float(value)
    return rates


class PriceTable:
    """The built-in table plus ``budget.yaml`` overrides."""

    def __init__(self, table: Mapping[str, Any], overrides: Mapping[str, Mapping[str, float]]
                 | None = None):
        self.as_of = str(table.get("as_of", ""))
        self._vendor_prefixes: dict[str, tuple[str, ...]] = {}
        self._models: dict[str, tuple[str, dict[str, float]]] = {}  # key -> (vendor, rates)
        for vendor, spec in (table.get("vendors") or {}).items():
            self._vendor_prefixes[vendor] = tuple(spec.get("prefixes") or ())
            for model, entry in (spec.get("models") or {}).items():
                rates = _check_rates(f"prices.yaml: {model}", entry, require_all=False)
                self._models[normalize_model(model)] = (vendor, rates)
        self._overrides = {normalize_model(m): dict(r) for m, r in (overrides or {}).items()}
        self._vendor_max: dict[str, dict[str, float]] = {}
        self._global_max: dict[str, float] = {}
        for vendor, rates in self._models.values():
            vmax = self._vendor_max.setdefault(vendor, {})
            for cat, rate in rates.items():
                vmax[cat] = max(vmax.get(cat, 0.0), rate)
                self._global_max[cat] = max(self._global_max.get(cat, 0.0), rate)

    def vendor_of(self, model: str, provider: str | None = None) -> str | None:
        """The vendor, from the log's provider field when it names one, else
        from the table entry or the model id's prefix; ``None`` if unknown."""
        if provider and provider.lower() in _PROVIDER_VENDOR:
            return _PROVIDER_VENDOR[provider.lower()]
        key = normalize_model(model)
        if key in self._models:
            return self._models[key][0]
        for vendor, prefixes in self._vendor_prefixes.items():
            if any(key.startswith(p.replace(".", "-")) for p in prefixes):
                return vendor
        return None

    def price(self, model: str, provider: str | None = None) -> Price:
        key = normalize_model(model)
        vendor = self.vendor_of(model, provider)
        if key in self._overrides:
            return Price(model, vendor, self._overrides[key])
        known = self._models[key][1] if key in self._models else {}
        fallback = self._vendor_max.get(vendor or "", {}) or self._global_max
        rates: dict[str, float] = {}
        estimated = set()
        for cat in CATEGORIES:
            if cat in known:
                rates[cat] = known[cat]
            else:
                rates[cat] = fallback.get(cat, self._global_max.get(cat, 0.0))
                estimated.add(cat)
        return Price(model, vendor, rates, frozenset(estimated))

    def cost(self, usage_by_model: Mapping[str, Mapping[str, int]],
             providers: Mapping[str, str] | None = None) -> Cost:
        """Dollars for ``{model: {category: tokens}}``. A model is reported as
        estimated only for categories it actually used."""
        total = Cost()
        for model, usage in usage_by_model.items():
            price = self.price(model, (providers or {}).get(model))
            used_estimates = sorted(c for c in price.estimated if usage.get(c, 0))
            total.add(Cost(price.cost(usage), {model: used_estimates} if used_estimates else {}))
        return total


def load_builtin_table() -> dict[str, Any]:
    """The built-in price table, from ``prices.json``: the same table as
    ``prices.yaml`` (the file people edit), generated by
    ``scripts/sync_prices.py`` and kept equal by a test. It is read from the
    installed package, never from a writable cache, so nothing but a signed
    ``pricing:`` override can change a price; and JSON loads in well under a
    millisecond where parsing the YAML on every hook call cost ~15 ms."""
    table = json.loads(resources.files("aegis_core.budget").joinpath("prices.json").read_text())
    if not isinstance(table, dict) or table.get("version") != 1:
        raise ValueError("aegis_core/budget/prices.json: unsupported shape or version")
    return table


def load_source_table() -> dict[str, Any]:
    """``prices.yaml`` itself (for the sync script and its test)."""
    return yaml.safe_load(
        resources.files("aegis_core.budget").joinpath("prices.yaml").read_text())


def check_override(where: str, entry: Any) -> dict[str, float]:
    """A ``budget.yaml`` price override: all four categories, numbers >= 0."""
    return _check_rates(where, entry, require_all=True)
