"""Cross-agent session budget cap (design: docs/dev/DESIGN-v1.0-budget-cap.md).

* :mod:`~aegis_core.budget.policy` -- the signed ``budget.yaml``;
* :mod:`~aegis_core.budget.pricing` -- tokens to estimated dollars;
* :mod:`~aegis_core.budget.logs` -- reading usage from each agent's logs;
* :mod:`~aegis_core.budget.accounting` -- session records, project/day
  totals, revisions, locks, the inventory and rebuilds;
* :mod:`~aegis_core.budget.evaluate` -- allow / warn / deny.
"""

from aegis_core.budget.accounting import BudgetStore, Snapshot, rebuild, refresh
from aegis_core.budget.evaluate import ALLOW, DENY, WARN, Verdict, evaluate
from aegis_core.budget.logs import Locator, default_logs
from aegis_core.budget.policy import BUDGET_CLASS, BUDGET_FILE, BudgetPolicy, load_budget_policy
from aegis_core.budget.pricing import PriceTable, load_builtin_table


def price_table(policy: BudgetPolicy) -> PriceTable:
    """The built-in prices with the policy's signed overrides."""
    return PriceTable(load_builtin_table(), policy.pricing)


__all__ = [
    "ALLOW", "BUDGET_CLASS", "BUDGET_FILE", "DENY", "WARN", "BudgetPolicy", "BudgetStore",
    "Locator", "PriceTable", "Snapshot", "Verdict", "default_logs", "evaluate",
    "load_budget_policy", "load_builtin_table", "price_table", "rebuild", "refresh",
]
