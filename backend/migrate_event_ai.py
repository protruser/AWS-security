"""Apply the additive event AI cache table before switching dashboard images.

The SQL is idempotent. A failure exits nonzero, so the deployment script leaves
the running dashboard container in place.
"""

from pathlib import Path

from db import get_connection


def main():
    migration = Path(__file__).resolve().parent / "migrations" / "006_add_event_ai_analyses.sql"
    sql = migration.read_text(encoding="utf-8")
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql)
            cursor.execute(
                "SELECT COUNT(*) AS count FROM information_schema.tables "
                "WHERE table_schema = DATABASE() AND table_name = %s",
                ("event_ai_analyses",),
            )
            if cursor.fetchone()["count"] != 1:
                raise RuntimeError("event_ai_analyses was not created")
    print("event_ai_analyses migration verified")


if __name__ == "__main__":
    main()
