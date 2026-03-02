"""
Threat detection engine.
Runs as a background task; periodically scans recent activity_logs
and fires threat events when suspicious patterns are detected.
"""

from __future__ import annotations
import asyncio
import logging
from collections import defaultdict
from datetime import datetime
from typing import Callable, Awaitable

import aiosqlite
import database as db
from config import (
    BRUTE_FORCE_THRESHOLD,
    PORT_SCAN_THRESHOLD,
    BRUTE_WINDOW_SECONDS,
    DB_PATH,
)

logger = logging.getLogger(__name__)

_INJECTION_PATTERNS = (
    "' OR", "1=1", "UNION SELECT", "DROP TABLE",
    "../", "etc/passwd", "<script>", "EXEC(",
    "xp_cmdshell", "WAITFOR DELAY",
)


class ThreatDetector:
    """Background coroutine that analyses logs every 10 seconds."""

    def __init__(self, broadcast: Callable[[dict], Awaitable[None]]):
        self._broadcast  = broadcast
        self._running    = False
        self._seen_ids: set[int] = set()

    async def start(self) -> None:
        self._running = True
        asyncio.ensure_future(self._loop())

    async def stop(self) -> None:
        self._running = False

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._analyse()
            except Exception as exc:
                logger.exception("Threat detector error: %s", exc)
            await asyncio.sleep(10)

    async def _analyse(self) -> None:
        window = f"-{BRUTE_WINDOW_SECONDS} seconds"
        async with aiosqlite.connect(DB_PATH) as db_conn:
            db_conn.row_factory = aiosqlite.Row

            # ── Brute force detection ──────────────────────────────────────────
            cur = await db_conn.execute(
                """SELECT source_ip, service, COUNT(*) AS cnt
                   FROM activity_logs
                   WHERE event_type = 'authentication'
                     AND success    = 0
                     AND timestamp  > datetime('now', ?)
                   GROUP BY source_ip, service
                   HAVING cnt >= ?""",
                (window, BRUTE_FORCE_THRESHOLD),
            )
            for row in await cur.fetchall():
                await self._fire_threat(
                    threat_type = "brute_force",
                    source_ip   = row["source_ip"],
                    target      = row["service"],
                    severity    = "high",
                    description = f"Brute force attack: {row['cnt']} failed logins on {row['service'].upper()}",
                    details     = {"count": row["cnt"]},
                )

            # ── Port scan detection ────────────────────────────────────────────
            cur = await db_conn.execute(
                """SELECT source_ip, COUNT(DISTINCT service) AS svc_count
                   FROM activity_logs
                   WHERE event_type = 'connection'
                     AND timestamp  > datetime('now', ?)
                   GROUP BY source_ip
                   HAVING svc_count >= ?""",
                (window, PORT_SCAN_THRESHOLD),
            )
            for row in await cur.fetchall():
                await self._fire_threat(
                    threat_type = "port_scan",
                    source_ip   = row["source_ip"],
                    target      = "multiple",
                    severity    = "medium",
                    description = f"Port scan detected: {row['svc_count']} services probed",
                    details     = {"services_hit": row["svc_count"]},
                )

            # ── SQL / code injection detection ────────────────────────────────
            cur = await db_conn.execute(
                """SELECT id, source_ip, service, details
                   FROM activity_logs
                   WHERE event_type IN ('authentication','command','file_access')
                     AND timestamp   > datetime('now', ?)""",
                (window,),
            )
            for row in await cur.fetchall():
                details_upper = row["details"].upper()
                for pat in _INJECTION_PATTERNS:
                    if pat in details_upper and row["id"] not in self._seen_ids:
                        await self._fire_threat(
                            threat_type = "injection",
                            source_ip   = row["source_ip"],
                            target      = row["service"],
                            severity    = "high",
                            description = f"Injection attempt on {row['service'].upper()}: {row['details'][:80]}",
                            details     = {"pattern": pat, "log_id": row["id"]},
                        )
                        self._seen_ids.add(row["id"])
                        break

            # ── High-volume DDoS-like detection ───────────────────────────────
            cur = await db_conn.execute(
                """SELECT source_ip, COUNT(*) AS cnt
                   FROM activity_logs
                   WHERE timestamp > datetime('now', '-60 seconds')
                   GROUP BY source_ip
                   HAVING cnt >= 30""",
            )
            for row in await cur.fetchall():
                await self._fire_threat(
                    threat_type = "ddos",
                    source_ip   = row["source_ip"],
                    target      = "honeypot",
                    severity    = "critical",
                    description = f"High-volume attack: {row['cnt']} requests in 60s from {row['source_ip']}",
                    details     = {"count": row["cnt"]},
                )

    async def _fire_threat(
        self,
        *,
        threat_type: str,
        source_ip: str,
        target: str,
        severity: str,
        description: str,
        details: dict | None = None,
    ) -> None:
        row_id = await db.log_threat(
            threat_type    = threat_type,
            source_ip      = source_ip,
            target_service = target,
            severity       = severity,
            description    = description,
            details        = details,
        )
        await self._broadcast({
            "event": "threat",
            "data": {
                "id":             row_id,
                "timestamp":      datetime.utcnow().isoformat(),
                "type":           threat_type,
                "source_ip":      source_ip,
                "target_service": target,
                "severity":       severity,
                "description":    description,
                "details":        None,
            },
        })
