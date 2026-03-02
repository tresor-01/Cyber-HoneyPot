"""
MySQL Honeypot  —  medium-interaction
Implements the MySQL Server Handshake protocol (v10) and captures
authentication attempts (plain-text and native-password).
"""

from __future__ import annotations
import asyncio
import logging
import struct
import os
from datetime import datetime

import database as db
from config import MYSQL_PORT, MYSQL_VERSION
from services import BaseHoneypotService

logger = logging.getLogger(__name__)


def _build_greeting() -> bytes:
    """Build a MySQL 8.x Server Greeting (HandshakeV10) packet."""
    version_bytes   = MYSQL_VERSION.encode() + b"\x00"
    thread_id       = struct.pack("<I", 1)
    auth_plugin_data_1 = os.urandom(8)
    filler          = b"\x00"
    capability_flags_1 = struct.pack("<H", 0xF7FF)
    charset         = b"\x08"  # latin1
    status_flags    = struct.pack("<H", 0x0002)
    capability_flags_2 = struct.pack("<H", 0x8181)
    auth_plugin_len = struct.pack("<B", 21)
    reserved        = b"\x00" * 10
    auth_plugin_data_2 = os.urandom(12) + b"\x00"
    auth_plugin_name   = b"mysql_native_password\x00"

    payload = (
        b"\x0a"  # protocol version
        + version_bytes
        + thread_id
        + auth_plugin_data_1
        + filler
        + capability_flags_1
        + charset
        + status_flags
        + capability_flags_2
        + auth_plugin_len
        + reserved
        + auth_plugin_data_2
        + auth_plugin_name
    )
    length   = struct.pack("<I", len(payload))[:3]
    seq      = b"\x00"
    return length + seq + payload


def _build_err_packet(code: int = 1045, msg: str = "Access denied") -> bytes:
    """Build a MySQL ERR_Packet."""
    payload = (
        b"\xff"
        + struct.pack("<H", code)
        + b"#28000"
        + msg.encode()
    )
    length = struct.pack("<I", len(payload))[:3]
    seq    = b"\x02"
    return length + seq + payload


class MySQLProtocol(asyncio.Protocol):
    def __init__(self, emit_fn):
        self._emit        = emit_fn
        self._transport   = None
        self._source_ip   = "unknown"
        self._source_port = 0
        self._buf         = b""
        self._greeted     = False

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport
        peer = transport.get_extra_info("peername")
        self._source_ip   = peer[0] if peer else "unknown"
        self._source_port = peer[1] if peer else 0
        asyncio.ensure_future(self._on_connect())

    def data_received(self, data: bytes):
        self._buf += data
        asyncio.ensure_future(self._process())

    def connection_lost(self, exc):
        asyncio.ensure_future(
            db.log_activity(
                event_type="disconnection", service="mysql",
                source_ip=self._source_ip, source_port=self._source_port,
                details="MySQL connection terminated", success=True,
            )
        )

    async def _on_connect(self):
        row_id = await db.log_activity(
            event_type="connection", service="mysql",
            source_ip=self._source_ip, source_port=self._source_port,
            details="New MySQL connection", success=True,
        )
        self._transport.write(_build_greeting())
        self._greeted = True
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                "event_type": "connection", "service": "mysql",
                "source_ip": self._source_ip, "source_port": self._source_port,
                "details": "New MySQL connection", "success": True, "raw_data": None,
            },
        })

    async def _process(self):
        while len(self._buf) >= 4:
            pkt_len = struct.unpack("<I", self._buf[:3] + b"\x00")[0]
            if len(self._buf) < 4 + pkt_len:
                break
            seq     = self._buf[3]
            payload = self._buf[4 : 4 + pkt_len]
            self._buf = self._buf[4 + pkt_len :]
            await self._handle_packet(seq, payload)

    async def _handle_packet(self, seq: int, payload: bytes):
        if not payload:
            return
        cmd = payload[0]

        if cmd == 0x03 and self._greeted:
            # COM_QUERY — extract username from login handshake
            # Login handshake: cap flags (4) + max pkt (4) + charset (1) + reserved (23) = 32 bytes
            try:
                if len(payload) > 36:
                    rest   = payload[36:]
                    username = rest.split(b"\x00")[0].decode(errors="ignore")
                    row_id = await db.log_activity(
                        event_type="authentication", service="mysql",
                        source_ip=self._source_ip, source_port=self._source_port,
                        details=f"MySQL login attempt for user: {username}",
                        success=False,
                        raw_data={"username": username},
                    )
                    await self._emit({
                        "event": "activity_log",
                        "data": {
                            "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                            "event_type": "authentication", "service": "mysql",
                            "source_ip": self._source_ip, "source_port": self._source_port,
                            "details": f"MySQL login attempt for user: {username}",
                            "success": False, "raw_data": None,
                        },
                    })
            except Exception:
                pass
            self._transport.write(_build_err_packet())

        elif len(payload) >= 32 and self._greeted:
            # Login response packet
            try:
                rest     = payload[32:]
                username = rest.split(b"\x00")[0].decode(errors="ignore")
                if username:
                    row_id = await db.log_activity(
                        event_type="authentication", service="mysql",
                        source_ip=self._source_ip, source_port=self._source_port,
                        details=f"MySQL login attempt for user: {username}",
                        success=False,
                        raw_data={"username": username},
                    )
                    await self._emit({
                        "event": "activity_log",
                        "data": {
                            "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                            "event_type": "authentication", "service": "mysql",
                            "source_ip": self._source_ip, "source_port": self._source_port,
                            "details": f"MySQL login attempt for user: {username}",
                            "success": False, "raw_data": None,
                        },
                    })
            except Exception:
                pass
            self._transport.write(_build_err_packet())
            self._transport.close()


class MySQLHoneypot(BaseHoneypotService):
    service_id = "mysql"
    port       = MYSQL_PORT

    async def start_server(self) -> None:
        loop    = asyncio.get_event_loop()
        emit_fn = self.emit
        self._server = await loop.create_server(
            lambda: MySQLProtocol(emit_fn), "0.0.0.0", self.port
        )
