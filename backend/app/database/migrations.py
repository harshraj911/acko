from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


SQLITE_ADDITIONS = {
    "findings": {
        "assigned_owner": "VARCHAR(160)",
        "due_date": "DATETIME",
        "remediation_notes": "TEXT NOT NULL DEFAULT ''",
        "risk_score": "INTEGER NOT NULL DEFAULT 0",
        "risk_breakdown_json": "TEXT NOT NULL DEFAULT '[]'",
        "fixed_version": "VARCHAR(120)",
        "upgrade_complexity": "VARCHAR(24) NOT NULL DEFAULT 'unknown'",
        "resolution_info": "TEXT",
        "verification_scan_id": "INTEGER",
        "updated_at": "DATETIME",
        "current_file": "VARCHAR(240)",
        "progress_percent": "FLOAT NOT NULL DEFAULT 0",
        "packages_inspected": "INTEGER NOT NULL DEFAULT 0",
        "vulnerabilities_discovered": "INTEGER NOT NULL DEFAULT 0",
    },
    "activity_logs": {
        "service_id": "INTEGER",
        "dependency_id": "INTEGER",
        "finding_id": "INTEGER",
    },
    "scan_sessions": {
        "current_file": "VARCHAR(240)",
        "progress_percent": "FLOAT NOT NULL DEFAULT 0",
        "packages_inspected": "INTEGER NOT NULL DEFAULT 0",
        "vulnerabilities_discovered": "INTEGER NOT NULL DEFAULT 0",
    },
}


def migrate_existing_sqlite(engine: Engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table, additions in SQLITE_ADDITIONS.items():
            if table not in inspector.get_table_names():
                continue
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, definition in additions.items():
                if name not in existing:
                    connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}'))
