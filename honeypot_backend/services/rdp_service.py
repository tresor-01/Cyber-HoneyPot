"""
RDP Honeypot  —  medium-interaction
Simulates a Windows Remote Desktop Protocol server (port 3389).
Captures connection attempts, NLA/SSL negotiation probes, and credential sprays.
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime

import database as db
from config import RDP_PORT
from services import BaseHoneypotService

logger = logging.getLogger(__name__)

# RDP Negotiation Response packet (TPKT + X.224 + NegoResp, NLA security selected)
_RDP_NEG_RSP = bytes([
    0x03, 0x00, 0x00, 0x13,   # TPKT header: version=3, length=19
    0x0e,                     # X.224 Data header length
    0xd0,                     # X.224 Connection Confirm
    0x00, 0x00,               # DST-REF
    0x00, 0x00,               # SRC-REF
    0x00,                     # Class / options
    0x02,                     # Type: RDP_NEG_RSP
    0x00,                     # Flags
    0x08, 0x00,               # Length: 8
    0x02, 0x00, 0x00, 0x00,   # selectedProtocol: PROTOCOL_HYBRID (NLA)
])


class RDPProtocol(asyncio.Protocol):
    def __init__(self, emit_fn):
        self._emit        = emit_fn
        self._transport   = None
        self._source_ip   = "unknown"
        self._source_port = 0
        self._greeted     = False

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
                service="rdp",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details="RDP connection terminated",
                success=True,
            )
        )

    def _write(self, data: bytes):
        if self._transport and not self._transport.is_closing():
            self._transport.write(data)

    async def _on_connect(self):
        row_id = await db.log_activity(
            event_type="connection",
            service="rdp",
            source_ip=self._source_ip,
            source_port=self._source_port,
            details="New RDP connection attempt",
            success=True,
        )
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                "event_type": "connection", "service": "rdp",
                "source_ip": self._source_ip, "source_port": self._source_port,
                "details": "New RDP connection attempt", "success": True, "raw_data": None,
            },
        })

    async def _handle(self, data: bytes):
        if not self._greeted and len(data) >= 4 and data[0] == 0x03:
            # TPKT / X.224 Connection Request → send Negotiation Response
            self._greeted = True
            self._write(_RDP_NEG_RSP)

            # Try to extract requested username from the cookie field
            try:
                text   = data.decode("ascii", errors="ignore")
                cookie = ""
                if "Cookie: mstshash=" in text:
                    cookie = text.split("Cookie: mstshash=")[1].split("\r\n")[0].strip()
            except Exception:
                cookie = ""

            details = f"RDP negotiation from {self._source_ip}"
            if cookie:
                details += f" — username hint: {cookie}"

            row_id = await db.log_activity(
                event_type="authentication",
                service="rdp",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details=details,
                success=False,
                raw_data={"username_hint": cookie} if cookie else None,
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "authentication", "service": "rdp",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": details, "success": False, "raw_data": None,
                },
            })
            # Drop connection — NLA requires TLS, we don't negotiate further
            self._transport.close()
        else:
            # Unexpected data after greeting
            self._transport.close()


class RDPHoneypot(BaseHoneypotService):
    service_id = "rdp"
    port       = RDP_PORT

    async def start_server(self) -> None:
        loop = asyncio.get_event_loop()
        self._server = await loop.create_server(
            lambda: RDPProtocol(self.emit),
            host  = "0.0.0.0",
            port  = self.port,
        )
