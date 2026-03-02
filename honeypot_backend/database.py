"""
Async SQLite database layer using aiosqlite.
"""

import aiosqlite
import json
from datetime import datetime
from typing import Optional
from config import DB_PATH

# ── Schema ─────────────────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS activity_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    service     TEXT    NOT NULL,
    source_ip   TEXT    NOT NULL,
    source_port INTEGER,
    details     TEXT    NOT NULL,
    success     INTEGER NOT NULL DEFAULT 0,
    raw_data    TEXT
);

CREATE TABLE IF NOT EXISTS threats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT  NOT NULL,
    type            TEXT  NOT NULL,
    source_ip       TEXT  NOT NULL,
    target_service  TEXT  NOT NULL,
    severity        TEXT  NOT NULL,
    description     TEXT  NOT NULL,
    details         TEXT
);

CREATE TABLE IF NOT EXISTS service_stats (
    service_id         TEXT    PRIMARY KEY,
    total_connections  INTEGER DEFAULT 0,
    failed_auths       INTEGER DEFAULT 0,
    commands_captured  INTEGER DEFAULT 0,
    last_activity      TEXT
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp   ON activity_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_source_ip   ON activity_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_logs_service     ON activity_logs(service);
CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
"""

# ── Connection helper ──────────────────────────────────────────────────────────

async def get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(DDL)
        await db.commit()

        # Seed service stats rows if missing
        services = ["ssh", "http", "ftp", "telnet", "mysql", "smtp",
                    "rdp", "vnc", "redis", "postgresql"]
        for svc in services:
            await db.execute(
                "INSERT OR IGNORE INTO service_stats (service_id) VALUES (?)", (svc,)
            )
        await db.commit()


# ── Write helpers ──────────────────────────────────────────────────────────────

async def log_activity(
    *,
    event_type: str,
    service: str,
    source_ip: str,
    source_port: Optional[int],
    details: str,
    success: bool = False,
    raw_data: Optional[dict] = None,
) -> int:
    ts = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """INSERT INTO activity_logs
               (timestamp, event_type, service, source_ip, source_port, details, success, raw_data)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                ts,
                event_type,
                service,
                source_ip,
                source_port,
                details,
                int(success),
                json.dumps(raw_data) if raw_data else None,
            ),
        )
        await db.execute(
            """UPDATE service_stats
               SET total_connections = total_connections + ?,
                   failed_auths = failed_auths + ?,
                   last_activity = ?
               WHERE service_id = ?""",
            (
                1 if event_type == "connection" else 0,
                1 if event_type == "authentication" and not success else 0,
                ts,
                service,
            ),
        )
        await db.execute(
            """UPDATE service_stats
               SET commands_captured = commands_captured + 1
               WHERE service_id = ? AND ? = 'command'""",
            (service, event_type),
        )
        await db.commit()
        return cur.lastrowid


async def log_threat(
    *,
    threat_type: str,
    source_ip: str,
    target_service: str,
    severity: str,
    description: str,
    details: Optional[dict] = None,
) -> int:
    ts = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """INSERT INTO threats
               (timestamp, type, source_ip, target_service, severity, description, details)
               VALUES (?,?,?,?,?,?,?)""",
            (
                ts,
                threat_type,
                source_ip,
                target_service,
                severity,
                description,
                json.dumps(details) if details else None,
            ),
        )
        await db.commit()
        return cur.lastrowid


# ── Read helpers ───────────────────────────────────────────────────────────────

async def get_logs(limit: int = 50, offset: int = 0) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM activity_logs ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_threats(limit: int = 50, offset: int = 0) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM threats ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_service_stats() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("""
            SELECT
                s.service_id,
                s.failed_auths,
                s.commands_captured,
                s.last_activity,
                COALESCE(l.cnt, 0) AS total_connections
            FROM service_stats s
            LEFT JOIN (
                SELECT service, COUNT(*) AS cnt
                FROM activity_logs
                WHERE event_type != 'disconnection'
                GROUP BY service
            ) l ON l.service = s.service_id
        """)
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_summary_stats() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        total_conn = (await (await db.execute(
            "SELECT COUNT(*) FROM activity_logs WHERE event_type != 'disconnection'"
        )).fetchone())[0]

        blocked = (await (await db.execute(
            "SELECT COUNT(*) FROM activity_logs WHERE success = 0 AND event_type = 'authentication'"
        )).fetchone())[0]

        active_threats = (await (await db.execute(
            "SELECT COUNT(*) FROM threats WHERE timestamp > datetime('now', '-5 minutes')"
        )).fetchone())[0]

        services_up = (await (await db.execute(
            "SELECT COUNT(*) FROM service_stats WHERE last_activity IS NOT NULL"
        )).fetchone())[0]

        return {
            "total_connections": total_conn,
            "blocked_attacks": blocked,
            "active_threats": active_threats,
            "services_running": services_up,
        }


async def get_recent_ips(service: str, window_seconds: int = 60) -> list[str]:
    """Return source IPs with failed auth in the last window_seconds for a service."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT source_ip, COUNT(*) as cnt
               FROM activity_logs
               WHERE service = ?
                 AND event_type = 'authentication'
                 AND success = 0
                 AND timestamp > datetime('now', ? || ' seconds')
               GROUP BY source_ip""",
            (service, f"-{window_seconds}"),
        )
        return [dict(r) for r in await cur.fetchall()]
