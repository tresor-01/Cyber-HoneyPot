"""
Redis Honeypot  —  medium-interaction
Simulates a Redis server (port 6379).
Captures: AUTH attempts, keyspace enumeration (KEYS, SCAN, GET),
          config reads (CONFIG GET), and arbitrary command probes.
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime

import database as db
from config import REDIS_PORT
from services import BaseHoneypotService

logger = logging.getLogger(__name__)

# Fake data returned for common Redis enumeration
_FAKE_KEYS = [
    "session:user:1001", "session:user:1042", "session:admin:9999",
    "cache:product:5517", "cache:homepage", "job:email:queue",
    "secret:api_key", "config:db_password",
]

_FAKE_CONFIG = {
    "bind":        "127.0.0.1",
    "requirepass": "**REDACTED**",
    "maxmemory":   "256mb",
    "dir":         "/var/lib/redis",
    "dbfilename":  "dump.rdb",
    "loglevel":    "notice",
}


def _bulk(s: str) -> bytes:
    enc = s.encode()
    return b"$" + str(len(enc)).encode() + b"\r\n" + enc + b"\r\n"

def _array(items: list[str]) -> bytes:
    out = b"*" + str(len(items)).encode() + b"\r\n"
    for item in items:
        out += _bulk(item)
    return out

def _simple(msg: str) -> bytes:
    return (f"+{msg}\r\n").encode()

def _error(msg: str) -> bytes:
    return (f"-ERR {msg}\r\n").encode()

def _int(n: int) -> bytes:
    return (f":{n}\r\n").encode()


class RedisProtocol(asyncio.Protocol):
    def __init__(self, emit_fn):
        self._emit        = emit_fn
        self._transport   = None
        self._source_ip   = "unknown"
        self._source_port = 0
        self._buf         = b""
        self._authed      = False

    def connection_made(self, transport: asyncio.Transport):
        self._transport   = transport
        peer              = transport.get_extra_info("peername")
        self._source_ip   = peer[0] if peer else "unknown"
        self._source_port = peer[1] if peer else 0
        asyncio.ensure_future(self._on_connect())

    def data_received(self, data: bytes):
        self._buf += data
        while b"\r\n" in self._buf:
            asyncio.ensure_future(self._process())
            break  # _process drains the buffer

    def connection_lost(self, exc):
        asyncio.ensure_future(
            db.log_activity(
                event_type="disconnection",
                service="redis",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details="Redis connection terminated",
                success=True,
            )
        )

    def _write(self, data: bytes):
        if self._transport and not self._transport.is_closing():
            self._transport.write(data)

    async def _on_connect(self):
        row_id = await db.log_activity(
            event_type="connection",
            service="redis",
            source_ip=self._source_ip,
            source_port=self._source_port,
            details="New Redis connection",
            success=True,
        )
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                "event_type": "connection", "service": "redis",
                "source_ip": self._source_ip, "source_port": self._source_port,
                "details": "New Redis connection", "success": True, "raw_data": None,
            },
        })

    async def _process(self):
        """Parse a single RESP command from buffer."""
        raw  = self._buf.decode("utf-8", errors="replace")
        self._buf = b""

        # Parse RESP inline or array format
        args: list[str] = []
        lines = raw.strip().split("\r\n")
        if lines and lines[0].startswith("*"):
            # Array format: *N\r\n$len\r\nword\r\n...
            try:
                n = int(lines[0][1:])
                for i in range(n):
                    args.append(lines[2 + i * 2])
            except Exception:
                args = raw.split()
        else:
            # Inline format
            args = raw.split()

        if not args:
            return

        cmd  = args[0].upper()
        rest = args[1:]

        await self._dispatch(cmd, rest, raw.strip())

    async def _dispatch(self, cmd: str, args: list[str], raw: str):
        if cmd == "PING":
            self._write(_simple("PONG"))

        elif cmd == "AUTH":
            password = args[0] if args else ""
            row_id   = await db.log_activity(
                event_type="authentication",
                service="redis",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details=f"AUTH attempt with password: {password}",
                success=False,
                raw_data={"password": password},
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "authentication", "service": "redis",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"AUTH attempt with password: {password}",
                    "success": False, "raw_data": None,
                },
            })
            # Accept the password to lure deeper enumeration
            self._authed = True
            self._write(_simple("OK"))

        elif cmd in ("KEYS", "SCAN"):
            pattern = args[0] if args else "*"
            row_id  = await db.log_activity(
                event_type="command",
                service="redis",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details=f"Key enumeration: {cmd} {pattern}",
                success=True,
                raw_data={"command": cmd, "pattern": pattern},
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "command", "service": "redis",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"Key enumeration: {cmd} {pattern}",
                    "success": True, "raw_data": None,
                },
            })
            if cmd == "SCAN":
                # SCAN returns [cursor, [keys]]
                cursor = _bulk("0")
                keys   = _array(_FAKE_KEYS)
                self._write(b"*2\r\n" + cursor + keys)
            else:
                self._write(_array(_FAKE_KEYS))

        elif cmd == "GET":
            key = args[0] if args else ""
            self._write(_bulk(f"<honeypot-value-for-{key}>"))

        elif cmd in ("SET", "DEL", "EXPIRE"):
            self._write(_simple("OK"))

        elif cmd == "CONFIG":
            sub = args[0].upper() if args else ""
            if sub == "GET":
                param = args[1] if len(args) > 1 else "*"
                pairs: list[str] = []
                for k, v in _FAKE_CONFIG.items():
                    if param == "*" or param in k:
                        pairs += [k, v]
                row_id = await db.log_activity(
                    event_type="command",
                    service="redis",
                    source_ip=self._source_ip,
                    source_port=self._source_port,
                    details=f"CONFIG GET {param} — config enumeration",
                    success=True,
                )
                await self._emit({
                    "event": "activity_log",
                    "data": {
                        "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                        "event_type": "command", "service": "redis",
                        "source_ip": self._source_ip, "source_port": self._source_port,
                        "details": f"CONFIG GET {param}", "success": True, "raw_data": None,
                    },
                })
                self._write(_array(pairs))
            else:
                self._write(_simple("OK"))

        elif cmd == "INFO":
            info = (
                "# Server\r\nredis_version:7.2.4\r\nos:Linux 5.15.0 x86_64\r\n"
                "# Clients\r\nconnected_clients:1\r\n"
                "# Memory\r\nused_memory_human:1.23M\r\n"
                "# Keyspace\r\ndb0:keys=8,expires=2\r\n"
            )
            self._write(_bulk(info))

        elif cmd in ("QUIT", "EXIT"):
            self._write(_simple("OK"))
            self._transport.close()

        else:
            row_id = await db.log_activity(
                event_type="command",
                service="redis",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details=f"Unknown Redis command: {raw[:120]}",
                success=False,
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "command", "service": "redis",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"Unknown command: {cmd}", "success": False, "raw_data": None,
                },
            })
            self._write(_error(f"unknown command '{cmd}'"))


class RedisHoneypot(BaseHoneypotService):
    service_id = "redis"
    port       = REDIS_PORT

    async def start_server(self) -> None:
        loop = asyncio.get_event_loop()
        self._server = await loop.create_server(
            lambda: RedisProtocol(self.emit),
            host = "0.0.0.0",
            port = self.port,
        )
