"""
VNC Honeypot  —  medium-interaction
Simulates a VNC/RFB server (port 5900).
Captures connection attempts, version negotiation, and auth probes.
"""

from __future__ import annotations
import asyncio
import logging
import struct
from datetime import datetime

import database as db
from config import VNC_PORT
from services import BaseHoneypotService

logger = logging.getLogger(__name__)

# RFB protocol states
_S_BANNER  = "banner"
_S_SECTYPE = "sectype"
_S_AUTH    = "auth"
_S_DONE    = "done"

# VNC Authentication challenge (16 random-looking bytes)
_VNC_CHALLENGE = bytes([
    0x6a, 0x3f, 0x1c, 0x8e, 0x4b, 0x72, 0xa9, 0x55,
    0x3d, 0x0f, 0xe2, 0x77, 0xc1, 0x84, 0x5a, 0x2b,
])


class VNCProtocol(asyncio.Protocol):
    def __init__(self, emit_fn):
        self._emit        = emit_fn
        self._transport   = None
        self._source_ip   = "unknown"
        self._source_port = 0
        self._state       = _S_BANNER
        self._auth_attempts = 0

    def connection_made(self, transport: asyncio.Transport):
        self._transport   = transport
        peer              = transport.get_extra_info("peername")
        self._source_ip   = peer[0] if peer else "unknown"
        self._source_port = peer[1] if peer else 0
        asyncio.ensure_future(self._on_connect())

    def data_received(self, data: bytes):
        asyncio.ensure_future(self._handle(data))

    def connection_lost(self, exc):
        asyncio.ensure_future(
            db.log_activity(
                event_type="disconnection",
                service="vnc",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details="VNC connection terminated",
                success=True,
            )
        )

    def _write(self, data: bytes):
        if self._transport and not self._transport.is_closing():
            self._transport.write(data)

    async def _on_connect(self):
        row_id = await db.log_activity(
            event_type="connection",
            service="vnc",
            source_ip=self._source_ip,
            source_port=self._source_port,
            details="New VNC connection",
            success=True,
        )
        # Send RFB version banner (server offers 3.8)
        self._write(b"RFB 003.008\n")
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                "event_type": "connection", "service": "vnc",
                "source_ip": self._source_ip, "source_port": self._source_port,
                "details": "New VNC connection", "success": True, "raw_data": None,
            },
        })

    async def _handle(self, data: bytes):
        if self._state == _S_BANNER:
            # Client echoes back its preferred version e.g. "RFB 003.008\n"
            client_ver = data.decode("ascii", errors="ignore").strip()
            logger.debug("[VNC] %s client version: %s", self._source_ip, client_ver)
            # Offer security type 2 = VNC Authentication
            self._write(bytes([1, 2]))  # 1 security type available: type 2
            self._state = _S_SECTYPE

        elif self._state == _S_SECTYPE:
            # Client selects security type (should be 0x02)
            if data and data[0] == 2:
                # Send 16-byte DES challenge
                self._write(_VNC_CHALLENGE)
                self._state = _S_AUTH
            else:
                self._transport.close()

        elif self._state == _S_AUTH:
            # Client sends 16-byte DES-encrypted response — capture it
            self._auth_attempts += 1
            resp_hex = data[:16].hex() if len(data) >= 16 else data.hex()
            details  = f"VNC auth response received (attempt {self._auth_attempts})"
            row_id   = await db.log_activity(
                event_type="authentication",
                service="vnc",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details=details,
                success=False,
                raw_data={"challenge_response": resp_hex},
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "authentication", "service": "vnc",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": details, "success": False, "raw_data": None,
                },
            })
            # Send SecurityResult: Failed (4-byte big-endian 1)
            self._write(struct.pack(">I", 1))
            # Send reason string
            reason = b"Authentication failed"
            self._write(struct.pack(">I", len(reason)) + reason)
            self._state = _S_DONE
            self._transport.close()


class VNCHoneypot(BaseHoneypotService):
    service_id = "vnc"
    port       = VNC_PORT

    async def start_server(self) -> None:
        loop = asyncio.get_event_loop()
        self._server = await loop.create_server(
            lambda: VNCProtocol(self.emit),
            host = "0.0.0.0",
            port = self.port,
        )
