"""
SMTP Honeypot  —  medium-interaction
Implements ESMTP EHLO/AUTH/MAIL FROM/RCPT TO/DATA flow.
Captures: sender/recipient addresses, full email body, AUTH credentials.
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime
from email import message_from_string

import database as db
from config import SMTP_PORT, SMTP_BANNER
from services import BaseHoneypotService

logger = logging.getLogger(__name__)


class _SMTPState:
    BANNER  = "banner"
    EHLO    = "ehlo"
    AUTH    = "auth"
    MAIL    = "mail"
    RCPT    = "rcpt"
    DATA    = "data"
    READING = "reading"


class SMTPProtocol(asyncio.Protocol):
    def __init__(self, emit_fn):
        self._emit        = emit_fn
        self._transport   = None
        self._source_ip   = "unknown"
        self._source_port = 0
        self._state       = _SMTPState.BANNER
        self._buf         = ""
        self._mail_from   = ""
        self._rcpt_to     = []
        self._data_lines  = []
        self._helo_domain = ""

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport
        peer = transport.get_extra_info("peername")
        self._source_ip   = peer[0] if peer else "unknown"
        self._source_port = peer[1] if peer else 0
        asyncio.ensure_future(self._on_connect())

    def data_received(self, data: bytes):
        self._buf += data.decode(errors="ignore")
        while "\r\n" in self._buf:
            line, self._buf = self._buf.split("\r\n", 1)
            asyncio.ensure_future(self._handle_line(line))

    def connection_lost(self, exc):
        asyncio.ensure_future(
            db.log_activity(
                event_type="disconnection", service="smtp",
                source_ip=self._source_ip, source_port=self._source_port,
                details="SMTP connection terminated", success=True,
            )
        )

    def _write(self, msg: str):
        if self._transport and not self._transport.is_closing():
            self._transport.write((msg + "\r\n").encode())

    async def _on_connect(self):
        row_id = await db.log_activity(
            event_type="connection", service="smtp",
            source_ip=self._source_ip, source_port=self._source_port,
            details="New SMTP connection", success=True,
        )
        self._write(SMTP_BANNER)
        self._state = _SMTPState.EHLO
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                "event_type": "connection", "service": "smtp",
                "source_ip": self._source_ip, "source_port": self._source_port,
                "details": "New SMTP connection", "success": True, "raw_data": None,
            },
        })

    async def _handle_line(self, line: str):
        # Reading DATA body lines
        if self._state == _SMTPState.READING:
            if line == ".":
                body = "\r\n".join(self._data_lines)
                row_id = await db.log_activity(
                    event_type="file_access", service="smtp",
                    source_ip=self._source_ip, source_port=self._source_port,
                    details=f"Email captured from {self._mail_from} to {', '.join(self._rcpt_to)}",
                    success=True,
                    raw_data={"from": self._mail_from, "to": self._rcpt_to, "body": body[:500]},
                )
                await self._emit({
                    "event": "activity_log",
                    "data": {
                        "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                        "event_type": "file_access", "service": "smtp",
                        "source_ip": self._source_ip, "source_port": self._source_port,
                        "details": f"Email captured from {self._mail_from} to {', '.join(self._rcpt_to)}",
                        "success": True, "raw_data": None,
                    },
                })
                self._write("250 2.0.0 Ok: queued as ABC123")
                self._state = _SMTPState.MAIL
                self._data_lines = []
            else:
                self._data_lines.append(line)
            return

        cmd = line.upper().split()[0] if line.strip() else ""
        arg = line[len(cmd):].strip() if cmd else ""

        if cmd in ("EHLO", "HELO"):
            self._helo_domain = arg
            self._write(f"250-corp-internal.local Hello [{self._source_ip}]")
            self._write("250-SIZE 52428800")
            self._write("250-AUTH PLAIN LOGIN")
            self._write("250-STARTTLS")
            self._write("250 HELP")
            self._state = _SMTPState.MAIL

        elif cmd == "AUTH":
            # Capture plaintext AUTH attempts
            parts = line.split(maxsplit=2)
            mech  = parts[1].upper() if len(parts) > 1 else ""
            creds = parts[2] if len(parts) > 2 else ""
            row_id = await db.log_activity(
                event_type="authentication", service="smtp",
                source_ip=self._source_ip, source_port=self._source_port,
                details=f"SMTP AUTH {mech} attempt: {creds}",
                success=False,
                raw_data={"mechanism": mech, "credentials": creds},
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "authentication", "service": "smtp",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"SMTP AUTH {mech} attempt: {creds}",
                    "success": False, "raw_data": None,
                },
            })
            self._write("334 ")  # Ask for credentials
            self._state = _SMTPState.AUTH

        elif self._state == _SMTPState.AUTH:
            # Second AUTH line (base64 credentials)
            row_id = await db.log_activity(
                event_type="authentication", service="smtp",
                source_ip=self._source_ip, source_port=self._source_port,
                details=f"SMTP AUTH credentials (b64): {line}",
                success=False,
                raw_data={"b64_credentials": line},
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "authentication", "service": "smtp",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"SMTP AUTH credentials (b64): {line}",
                    "success": False, "raw_data": None,
                },
            })
            self._write("535 5.7.8 Authentication credentials invalid")
            self._state = _SMTPState.MAIL

        elif cmd == "MAIL":
            self._mail_from = arg.replace("FROM:", "").strip().strip("<>")
            self._write("250 2.1.0 Ok")
            self._state = _SMTPState.RCPT

        elif cmd == "RCPT":
            rcpt = arg.replace("TO:", "").strip().strip("<>")
            self._rcpt_to.append(rcpt)
            self._write("250 2.1.5 Ok")

        elif cmd == "DATA":
            self._write("354 End data with <CR><LF>.<CR><LF>")
            self._state = _SMTPState.READING

        elif cmd == "QUIT":
            self._write("221 2.0.0 Bye")
            if self._transport:
                self._transport.close()

        elif cmd == "RSET":
            self._mail_from = ""
            self._rcpt_to   = []
            self._write("250 2.0.0 Ok")

        elif cmd == "NOOP":
            self._write("250 2.0.0 Ok")

        elif cmd:
            self._write(f"500 5.5.2 Syntax error, unrecognized command '{cmd}'")


class SMTPHoneypot(BaseHoneypotService):
    service_id = "smtp"
    port       = SMTP_PORT

    async def start_server(self) -> None:
        loop    = asyncio.get_event_loop()
        emit_fn = self.emit
        self._server = await loop.create_server(
            lambda: SMTPProtocol(emit_fn), "0.0.0.0", self.port
        )
