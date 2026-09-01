from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS reservations (
    ip TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mac TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    active_count INTEGER NOT NULL,
    issue_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    level TEXT NOT NULL,
    message TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    # All values are passed separately from SQL strings. This is the
    # parameterized-query protection against SQL injection required by the task.
    def list_reservations(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT ip, name, mac, owner, note FROM reservations ORDER BY ip"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_reservation(self, ip: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT ip, name, mac, owner, note FROM reservations WHERE ip = ?",
                (ip,),
            ).fetchone()
        return dict(row) if row else None

    def upsert_reservation(self, reservation: dict, original_ip: str | None = None) -> None:
        with self.connect() as conn:
            if original_ip and original_ip != reservation["ip"]:
                conn.execute("DELETE FROM reservations WHERE ip = ?", (original_ip,))

            conn.execute(
                """
                INSERT INTO reservations (ip, name, mac, owner, note)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    name = excluded.name,
                    mac = excluded.mac,
                    owner = excluded.owner,
                    note = excluded.note,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    reservation["ip"],
                    reservation["name"],
                    reservation.get("mac", ""),
                    reservation.get("owner", ""),
                    reservation.get("note", ""),
                ),
            )

    def delete_reservation(self, ip: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM reservations WHERE ip = ?", (ip,))
            return cur.rowcount > 0

    def replace_reservations(self, reservations: Iterable[dict]) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM reservations")
            conn.executemany(
                "INSERT INTO reservations (ip, name, mac, owner, note) VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        item["ip"],
                        item["name"],
                        item.get("mac", ""),
                        item.get("owner", ""),
                        item.get("note", ""),
                    )
                    for item in reservations
                ],
            )

    def add_log(self, level: str, message: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO logs (level, message) VALUES (?, ?)",
                (level, message),
            )

    def list_logs(self, limit: int = 250, level: str | None = None) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self.connect() as conn:
            if level:
                rows = conn.execute(
                    """
                    SELECT id, created_at AS time, level, message
                    FROM logs
                    WHERE level = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (level, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, created_at AS time, level, message
                    FROM logs
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    def clear_logs(self) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM logs")

    def save_scan(
        self,
        *,
        cidr: str,
        started_at: str,
        finished_at: str,
        devices: list[dict],
    ) -> int:
        issue_count = sum(1 for d in devices if d["status"] != "good")
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scan_runs
                    (cidr, started_at, finished_at, active_count, issue_count)
                VALUES (?, ?, ?, ?, ?)
                """,
                (cidr, started_at, finished_at, len(devices), issue_count),
            )
            scan_id = int(cur.lastrowid)
            conn.executemany(
                """
                INSERT INTO scan_devices
                    (scan_id, ip, mac, name, status, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        d["ip"],
                        d["mac"],
                        d.get("name", ""),
                        d["status"],
                        d.get("reason", ""),
                    )
                    for d in devices
                ],
            )
        return scan_id

    def list_scans(self, limit: int = 25) -> list[dict]:
        limit = max(1, min(int(limit), 250))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, cidr, started_at, finished_at, active_count, issue_count
                FROM scan_runs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_scan(self) -> dict | None:
        with self.connect() as conn:
            run = conn.execute(
                """
                SELECT id, cidr, started_at, finished_at, active_count, issue_count
                FROM scan_runs
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
            if not run:
                return None
            devices = conn.execute(
                """
                SELECT ip, mac, name, status, reason
                FROM scan_devices
                WHERE scan_id = ?
                ORDER BY ip
                """,
                (run["id"],),
            ).fetchall()
        result = dict(run)
        result["devices"] = [dict(row) for row in devices]
        return result
