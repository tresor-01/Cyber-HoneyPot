"""
FTP Honeypot  —  medium-interaction
Pure asyncio TCP server implementing the core FTP command set.
Captures credentials, directory listings, and file transfer attempts.
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime

import database as db
from config import FTP_PORT, FTP_BANNER
from services import BaseHoneypotService

logger = logging.getLogger(__name__)

FAKE_LIST = (
    "-rw-r--r-- 1 root root    4096 Jan 15 10:23 backup.tar.gz\r\n"
    "-rw-r--r-- 1 root root    1024 Jan 10 08:00 config.ini\r\n"
    "-rw-r--r-- 1 root root  204800 Jan 12 14:55 database_dump.sql\r\n"
    "drwxr-xr-x 2 root root    4096 Jan  5 09:00 logs\r\n"
    "-rw------- 1 root root     512 Dec 30 22:11 .ssh_key\r\n"
)


class FTPProtocol(asyncio.Protocol):
    def __init__(self, emit_fn):
        self._emit        = emit_fn
        self._transport   = None
        self._source_ip   = "unknown"
        self._source_port = 0
        self._username    = ""
        self._password    = ""
        self._logged_in   = False
        self._passive_server: asyncio.AbstractServer | None = None
        self._passive_port = 0

    # ── asyncio.Protocol callbacks ─────────────────────────────────────────────

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport
        peer = transport.get_extra_info("peername")
        self._source_ip   = peer[0] if peer else "unknown"
        self._source_port = peer[1] if peer else 0
        asyncio.ensure_future(self._on_connect())

    def data_received(self, data: bytes):
        lines = data.decode(errors="ignore").strip().split("\r\n")
        for line in lines:
            if line:
                asyncio.ensure_future(self._handle_cmd(line))

    def connection_lost(self, exc):
        asyncio.ensure_future(
            db.log_activity(
                event_type="disconnection",
                service="ftp",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details="FTP connection terminated",
                success=True,
            )
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _write(self, msg: str):
        if self._transport and not self._transport.is_closing():
            self._transport.write((msg + "\r\n").encode())

    async def _on_connect(self):
        row_id = await db.log_activity(
            event_type="connection",
            service="ftp",
            source_ip=self._source_ip,
            source_port=self._source_port,
            details="New FTP connection",
            success=True,
        )
        self._write(FTP_BANNER)
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                "event_type": "connection", "service": "ftp",
                "source_ip": self._source_ip, "source_port": self._source_port,
                "details": "New FTP connection", "success": True, "raw_data": None,
            },
        })

    async def _handle_cmd(self, line: str):
        parts   = line.split(" ", 1)
        cmd     = parts[0].upper()
        arg     = parts[1] if len(parts) > 1 else ""

        if cmd == "USER":
            self._username = arg
            self._write(f"331 Password required for {arg}")

        elif cmd == "PASS":
            self._password = arg
            row_id = await db.log_activity(
                event_type="authentication",
                service="ftp",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details=f"Login attempt with credentials {self._username}:{self._password}",
                success=False,
                raw_data={"username": self._username, "password": self._password},
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "authentication", "service": "ftp",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"Login attempt with credentials {self._username}:{self._password}",
                    "success": False, "raw_data": None,
                },
            })
            # Allow login to capture further actions
            self._logged_in = True
            self._write(f"230 Login successful for {self._username}")

        elif cmd == "SYST":
            self._write("215 UNIX Type: L8")

        elif cmd == "FEAT":
            self._write("211-Features:\r\n PASV\r\n UTF8\r\n SIZE\r\n211 End")

        elif cmd == "TYPE":
            self._write("200 Type set to I")

        elif cmd == "PWD":
            self._write('257 "/" is the current directory')

        elif cmd == "CWD":
            self._write(f"250 Directory successfully changed to /{arg}")

        elif cmd == "PASV":
            # Bind a random high port for passive data transfer
            loop = asyncio.get_event_loop()
            server = await loop.create_server(
                lambda: asyncio.Protocol(), "0.0.0.0", 0
            )
            self._passive_port  = server.sockets[0].getsockname()[1]
            self._passive_server = server
            p1, p2 = self._passive_port >> 8, self._passive_port & 0xFF
            self._write(f"227 Entering Passive Mode (127,0,1,1,{p1},{p2})")

        elif cmd == "LIST":
            self._write("150 Here comes the directory listing")
            self._write(f"226 Directory send OK\r\n{FAKE_LIST}")
            row_id = await db.log_activity(
                event_type="file_access",
                service="ftp",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details="Listed directory contents",
                success=True,
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "file_access", "service": "ftp",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": "Listed directory contents", "success": True, "raw_data": None,
                },
            })

        elif cmd in ("RETR", "STOR"):
            action = "download" if cmd == "RETR" else "upload"
            row_id = await db.log_activity(
                event_type="file_access",
                service="ftp",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details=f"Attempted {action} of file: {arg}",
                success=False,
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "file_access", "service": "ftp",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"Attempted {action} of file: {arg}",
                    "success": False, "raw_data": None,
                },
            })
            self._write("550 Permission denied")

        elif cmd == "QUIT":
            self._write("221 Goodbye")
            if self._transport:
                self._transport.close()

        else:
            self._write(f"500 Unknown command '{cmd}'")


class FTPHoneypot(BaseHoneypotService):
    service_id = "ftp"
    port       = FTP_PORT

    async def start_server(self) -> None:
        loop = asyncio.get_event_loop()
        emit_fn = self.emit
        self._server = await loop.create_server(
            lambda: FTPProtocol(emit_fn), "0.0.0.0", self.port
        )
