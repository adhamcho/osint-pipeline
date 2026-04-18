from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from osint_pipeline.models import Finding, RunRecord


def get_default_db_path(base_dir: Path) -> Path:
    return base_dir / "data" / "osint_pipeline.db"


def ensure_database(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as connection:
        # `runs` stores one record per CLI execution.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                input_type TEXT NOT NULL,
                input_value TEXT NOT NULL,
                full_name TEXT,
                source TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                finding_count INTEGER NOT NULL
            )
            """
        )
        _ensure_runs_column(connection, "full_name", "TEXT")
        # `findings` stores normalized results tied back to a single run.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                input_type TEXT NOT NULL,
                input_value TEXT NOT NULL,
                platform TEXT NOT NULL,
                signal_strength TEXT NOT NULL DEFAULT 'low',
                url TEXT NOT NULL,
                username TEXT NOT NULL,
                source TEXT NOT NULL,
                checked_at_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                confidence TEXT,
                raw_data TEXT NOT NULL DEFAULT '{}',
                notes TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES runs(run_id)
            )
            """
        )
        _ensure_runs_column(connection, "created_at_utc", "TEXT")
        _backfill_run_created_at(connection)
        _ensure_findings_column(connection, "signal_strength", "TEXT NOT NULL DEFAULT 'low'")
        _ensure_findings_column(connection, "checked_at_utc", "TEXT")
        _ensure_findings_column(connection, "raw_data", "TEXT NOT NULL DEFAULT '{}'")
        _backfill_finding_checked_at(connection)
        _backfill_finding_raw_data(connection)
        connection.commit()


def _ensure_runs_column(connection: sqlite3.Connection, column_name: str, column_definition: str) -> None:
    existing_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()
    }
    if column_name not in existing_columns:
        connection.execute(f"ALTER TABLE runs ADD COLUMN {column_name} {column_definition}")


def _ensure_findings_column(connection: sqlite3.Connection, column_name: str, column_definition: str) -> None:
    existing_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(findings)").fetchall()
    }
    if column_name not in existing_columns:
        connection.execute(f"ALTER TABLE findings ADD COLUMN {column_name} {column_definition}")


def _backfill_run_created_at(connection: sqlite3.Connection) -> None:
    run_columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()}
    if "started_at" in run_columns:
        connection.execute(
            """
            UPDATE runs
            SET created_at_utc = COALESCE(created_at_utc, started_at)
            WHERE created_at_utc IS NULL OR created_at_utc = ''
            """
        )


def _backfill_finding_checked_at(connection: sqlite3.Connection) -> None:
    finding_columns = {row[1] for row in connection.execute("PRAGMA table_info(findings)").fetchall()}
    if "timestamp" in finding_columns:
        connection.execute(
            """
            UPDATE findings
            SET checked_at_utc = COALESCE(checked_at_utc, timestamp)
            WHERE checked_at_utc IS NULL OR checked_at_utc = ''
            """
        )


def _backfill_finding_raw_data(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        UPDATE findings
        SET raw_data = '{}'
        WHERE raw_data IS NULL OR raw_data = ''
        """
    )


def insert_run(db_path: Path, run: RunRecord) -> None:
    with sqlite3.connect(db_path) as connection:
        run_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()
        }
        columns = ["run_id", "input_type", "input_value", "full_name", "source", "created_at_utc", "finding_count"]
        values = [
            run.run_id,
            run.input_type,
            run.input_value,
            run.full_name,
            run.source,
            run.created_at_utc,
            run.finding_count,
        ]
        if "started_at" in run_columns:
            columns.append("started_at")
            values.append(run.created_at_utc)

        placeholders = ", ".join("?" for _ in columns)
        connection.execute(
            f"INSERT INTO runs ({', '.join(columns)}) VALUES ({placeholders})",
            tuple(values),
        )
        connection.commit()


def insert_findings(db_path: Path, findings: list[Finding]) -> None:
    with sqlite3.connect(db_path) as connection:
        finding_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(findings)").fetchall()
        }
        columns = [
            "run_id",
            "input_type",
            "input_value",
            "platform",
            "signal_strength",
            "url",
            "username",
            "source",
            "checked_at_utc",
            "status",
            "confidence",
            "raw_data",
            "notes",
        ]
        if "timestamp" in finding_columns:
            columns.append("timestamp")

        placeholders = ", ".join("?" for _ in columns)
        connection.executemany(
            f"INSERT INTO findings ({', '.join(columns)}) VALUES ({placeholders})",
            [
                tuple(
                    [
                    finding.run_id,
                    finding.input_type,
                    finding.input_value,
                    finding.platform,
                    finding.signal_strength,
                    finding.url,
                    finding.username,
                    finding.source,
                    finding.checked_at_utc,
                    finding.status,
                    finding.confidence,
                    finding.raw_data,
                    finding.notes,
                    ]
                    + ([finding.checked_at_utc] if "timestamp" in finding_columns else [])
                )
                for finding in findings
            ],
        )
        connection.commit()


def fetch_run(db_path: Path, run_id: str) -> tuple[tuple, list[tuple]]:
    with sqlite3.connect(db_path) as connection:
        run = connection.execute(
            "SELECT run_id, input_type, input_value, full_name, source, created_at_utc, finding_count FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        findings = connection.execute(
            """
            SELECT run_id, input_type, input_value, platform, signal_strength, url, username, source,
                   checked_at_utc, status, confidence, raw_data, notes
            FROM findings
            WHERE run_id = ?
            ORDER BY platform
            """,
            (run_id,),
        ).fetchall()
    return run, findings


def list_runs(db_path: Path, limit: int = 10) -> list[RunRecord]:
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT rowid, run_id, input_type, input_value, full_name, source, created_at_utc, finding_count
            FROM runs
            ORDER BY created_at_utc DESC, rowid DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        RunRecord(
            run_id=row[1],
            input_type=row[2],
            input_value=row[3],
            full_name=row[4],
            source=row[5],
            created_at_utc=row[6],
            finding_count=row[7],
        )
        for row in rows
    ]


def get_latest_run(db_path: Path) -> RunRecord | None:
    runs = list_runs(db_path, limit=1)
    return runs[0] if runs else None


def get_previous_run_for(db_path: Path, run: RunRecord) -> RunRecord | None:
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT rowid, run_id, input_type, input_value, full_name, source, created_at_utc, finding_count
            FROM runs
            WHERE input_type = ?
              AND input_value = ?
              AND COALESCE(full_name, '') = COALESCE(?, '')
              AND run_id != ?
            ORDER BY created_at_utc DESC, rowid DESC
            LIMIT 1
            """,
            (run.input_type, run.input_value, run.full_name, run.run_id),
        ).fetchone()
    if row is None:
        return None
    return RunRecord(
        run_id=row[1],
        input_type=row[2],
        input_value=row[3],
        full_name=row[4],
        source=row[5],
        created_at_utc=row[6],
        finding_count=row[7],
    )


def load_run_details(db_path: Path, run_id: str) -> tuple[RunRecord | None, list[Finding]]:
    run_row, finding_rows = fetch_run(db_path, run_id)
    if run_row is None:
        return None, []

    run = RunRecord(
        run_id=run_row[0],
        input_type=run_row[1],
        input_value=run_row[2],
        full_name=run_row[3],
        source=run_row[4],
        created_at_utc=run_row[5],
        finding_count=run_row[6],
    )
    findings = [
        Finding(
            run_id=row[0],
            input_type=row[1],
            input_value=row[2],
            platform=row[3],
            signal_strength=row[4],
            url=row[5],
            username=row[6],
            source=row[7],
            checked_at_utc=row[8],
            status=row[9],
            confidence=row[10],
            raw_data=row[11] if row[11] else json.dumps({}),
            notes=row[12],
        )
        for row in finding_rows
    ]
    return run, findings
