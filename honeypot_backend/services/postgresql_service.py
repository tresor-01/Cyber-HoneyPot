"""
PostgreSQL Honeypot  —  medium-interaction
Simulates a PostgreSQL server (port 5432).
Captures: startup packets (database/user names), password auth probes,
          and arbitrary query strings.
"""

from __future__ import annotations
import asyncio
import logging
import struct
from datetime import datetime

import database as db
from config import PGSQL_PORT
from services import BaseHoneypotService

logger = logging.getLogger(__name__)

# PostgreSQL message type constants
_AUTH_MD5      = b'R' + struct.pack(">I", 12) + struct.pack(">I", 5)
_AUTH_OK       = b'R' + struct.pack(">I", 8)  + struct.pack(">I", 0)
_READY_FOR_QUERY = b'Z' + struct.pack(">I", 5) + b'I'  # idle

def _error_response(msg: str) -> bytes:
    """Build a minimal PostgreSQL ErrorResponse packet."""
    fields = b'S' + b'FATAL\x00' + b'M' + msg.encode() + b'\x00' + b'\x00'
    return b'E' + struct.pack(">I", 4 + len(fields)) + fields

def _parameter_status(name: str, value: str) -> bytes:
    payload = name.encode() + b'\x00' + value.encode() + b'\x00'
    return b'S' + struct.pack(">I", 4 + len(payload)) + payload

def _notice(msg: str) -> bytes:
    fields = b'S' + b'NOTICE\x00' + b'M' + msg.encode() + b'\x00' + b'\x00'
    return b'N' + struct.pack(">I", 4 + len(fields)) + fields

# Fake MD5 salt
_SALT = b'\x2f\xa1\xd3\x99'


class PGSQLProtocol(asyncio.Protocol):
    def __init__(self, emit_fn):
        self._emit        = emit_fn
        self._transport   = None
        self._source_ip   = "unknown"
        self._source_port = 0
        self._buf         = b""
        self._state       = "startup"   # startup → auth → query → done
        self._pg_user     = ""
        self._pg_database = ""

    def connection_made(self, transport: asyncio.Transport):
        self._transport   = transport
        peer              = transport.get_extra_info("peername")
        self._source_ip   = peer[0] if peer else "unknown"
        self._source_port = peer[1] if peer else 0
        asyncio.ensure_future(self._on_connect())

    def data_received(self, data: bytes):
        self._buf += data
        asyncio.ensure_future(self._process())

    def connection_lost(self, exc):
        asyncio.ensure_future(
            db.log_activity(
                event_type="disconnection",
                service="postgresql",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details="PostgreSQL connection terminated",
                success=True,
            )
        )

    def _write(self, data: bytes):
        if self._transport and not self._transport.is_closing():
            self._transport.write(data)

    async def _on_connect(self):
        row_id = await db.log_activity(
            event_type="connection",
            service="postgresql",
            source_ip=self._source_ip,
            source_port=self._source_port,
            details="New PostgreSQL connection",
            success=True,
        )
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                "event_type": "connection", "service": "postgresql",
                "source_ip": self._source_ip, "source_port": self._source_port,
                "details": "New PostgreSQL connection", "success": True, "raw_data": None,
            },
        })

    async def _process(self):
        data = self._buf
        self._buf = b""

        if self._state == "startup":
            await self._handle_startup(data)
        elif self._state == "auth":
            await self._handle_auth(data)
        elif self._state == "query":
            await self._handle_query(data)

    async def _handle_startup(self, data: bytes):
        if len(data) < 8:
            return
        try:
            length  = struct.unpack(">I", data[:4])[0]
            version = struct.unpack(">I", data[4:8])[0]
        except Exception:
            self._transport.close()
            return

        if version == 80877103:
            # SSLRequest — decline SSL
            self._write(b'N')
            return

        # Parse startup parameters (null-terminated key=value pairs)
        params_raw = data[8:length].decode("utf-8", errors="replace")
        params: dict[str, str] = {}
        parts = params_raw.split('\x00')
        for i in range(0, len(parts) - 1, 2):
            if parts[i]:
                params[parts[i]] = parts[i + 1]

        self._pg_user     = params.get("user",     "unknown")
        self._pg_database = params.get("database", "unknown")

        row_id = await db.log_activity(
            event_type="authentication",
            service="postgresql",
            source_ip=self._source_ip,
            source_port=self._source_port,
            details=f"PostgreSQL startup: user={self._pg_user} db={self._pg_database}",
            success=False,
            raw_data={"user": self._pg_user, "database": self._pg_database},
        )
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                "event_type": "authentication", "service": "postgresql",
                "source_ip": self._source_ip, "source_port": self._source_port,
                "details": f"Startup: user={self._pg_user} db={self._pg_database}",
                "success": False, "raw_data": None,
            },
        })

        # Request MD5 password auth
        auth_md5 = b'R' + struct.pack(">I", 12) + struct.pack(">I", 5) + _SALT
        self._write(auth_md5)
        self._state = "auth"

    async def _handle_auth(self, data: bytes):
        if not data:
            return
        msg_type = data[0:1]
        if msg_type == b'p' and len(data) >= 5:
            # PasswordMessage
            length   = struct.unpack(">I", data[1:5])[0]
            password = data[5:5 + length - 5].decode("utf-8", errors="replace").rstrip('\x00')

            row_id = await db.log_activity(
                event_type="authentication",
                service="postgresql",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details=f"Password auth: user={self._pg_user} password={password}",
                success=False,
                raw_data={"user": self._pg_user, "password": password},
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "authentication", "service": "postgresql",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"Password: user={self._pg_user}",
                    "success": False, "raw_data": None,
                },
            })
            # Send auth failure
            err = _error_response(f"password authentication failed for user \"{self._pg_user}\"")
            self._write(err)
            self._state = "done"
            self._transport.close()
        else:
            self._transport.close()

    async def _handle_query(self, data: bytes):
        if not data:
            return
        if data[0:1] == b'Q' and len(data) >= 5:
            query = data[5:].decode("utf-8", errors="replace").rstrip('\x00')
            await db.log_activity(
                event_type="command",
                service="postgresql",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details=f"Query: {query[:200]}",
                success=True,
            )
        self._transport.close()


class PostgreSQLHoneypot(BaseHoneypotService):
    service_id = "postgresql"
    port       = PGSQL_PORT

    async def start_server(self) -> None:
        loop = asyncio.get_event_loop()
        self._server = await loop.create_server(
            lambda: PGSQLProtocol(self.emit),
            host = "0.0.0.0",
            port = self.port,
        )
