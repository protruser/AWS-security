"""Explicit, additive migration. Does not run on application startup."""
from pathlib import Path
from db import get_connection


def main():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            for name in ("007_add_terraform_patches.sql", "008_add_terraform_deploy_lock.sql"):
                sql = "\n".join(line for line in
                    (Path(__file__).parent / "migrations" / name).read_text(encoding="utf-8").splitlines()
                    if not line.lstrip().startswith("--"))
                for statement in sql.split(";"):
                    # The checked-in migration files have no semicolons in comments.
                    if statement.strip():
                        cursor.execute(statement)
    print("terraform_patches migration complete")


if __name__ == "__main__":
    main()
