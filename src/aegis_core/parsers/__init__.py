"""Work Section D: SQL + Pulumi parsers.

Turns raw SQL text / DB-CLI argv / migration-tool argv and Pulumi preview
JSON / argv into structured InfrastructureIntents, following the same
shape as :mod:`aegis_core.parser`.
"""

from aegis_core.parsers.pulumi import from_pulumi_argv, from_pulumi_preview
from aegis_core.parsers.sql import (
    from_migration_argv,
    from_mongosh,
    from_mysql,
    from_psql,
    from_sql,
    from_sqlite3,
)

__all__ = [
    "from_sql",
    "from_psql",
    "from_mysql",
    "from_sqlite3",
    "from_mongosh",
    "from_migration_argv",
    "from_pulumi_preview",
    "from_pulumi_argv",
]
