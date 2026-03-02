"""
Telnet Honeypot  —  medium-interaction
Pure asyncio TCP server with Telnet negotiation and interactive login.
Captures credentials and commands typed at the fake shell.
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime

import database as db
from config import TELNET_PORT, TELNET_BANNER
from services import BaseHoneypotService

logger = logging.getLogger(__name__)

# Telnet negotiation bytes we send on connect
_IAC  = bytes([255])
_WILL = bytes([251])
_ECHO = bytes([1])
_SGA  = bytes([3])

TELNET_NEGOTIATE = _IAC + _WILL + _ECHO + _IAC + _WILL + _SGA

MOTD = (
    "\r\n"
    "Ubuntu 22.04.3 LTS\r\n"
    "Authorized users only. All activity is monitored.\r\n"
    "\r\n"
)

FAKE_SHELL_RESPONSES = {
    "ls":           "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n",
    "whoami":       "root\r\n",
    "id":           "uid=0(root) gid=0(root) groups=0(root)\r\n",
    "uname -a":     "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n",
    "ifconfig":     "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>\r\n  inet 192.168.1.100  netmask 255.255.255.0\r\n",
    "ps":           "  PID TTY          TIME CMD\r\n    1 ?        00:00:03 init\r\n  456 ?        00:00:00 telnetd\r\n",
    "exit":         "",
    "logout":       "",
}

class _TelnetState:
    CONNECTING = "connecting"
    AUTH_USER  = "auth_user"
    AUTH_PASS  = "auth_pass"
    SHELL      = "shell"


class TelnetProtocol(asyncio.Protocol):
    def __init__(self, emit_fn):
        self._emit        = emit_fn
        self._transport   = None
        self._source_ip   = "unknown"
        self._source_port = 0
        self._username    = ""
        self._state       = _TelnetState.CONNECTING
        self._buf         = b""
        self._fail_count  = 0

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport
        peer = transport.get_extra_info("peername")
        self._source_ip   = peer[0] if peer else "unknown"
        self._source_port = peer[1] if peer else 0
        asyncio.ensure_future(self._on_connect())

    def data_received(self, data: bytes):
        # Strip IAC negotiation sequences from client
        filtered = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 255 and i + 2 < len(data):
                i += 3  # Skip IAC + verb + option
            else:
                filtered.append(data[i])
                i += 1
        self._buf += bytes(filtered)
        if b"\n" in self._buf or b"\r" in self._buf:
            line = self._buf.decode(errors="ignore").replace("\r\n", "\n").replace("\r", "\n")
            parts = line.split("\n")
            for part in parts[:-1]:
                asyncio.ensure_future(self._handle_line(part.strip()))
            self._buf = parts[-1].encode()

    def connection_lost(self, exc):
        asyncio.ensure_future(
            db.log_activity(
                event_type="disconnection", service="telnet",
                source_ip=self._source_ip, source_port=self._source_port,
                details="Telnet connection terminated", success=True,
            )
        )

    def _write(self, text: str):
        if self._transport and not self._transport.is_closing():
            self._transport.write(text.encode())

    async def _on_connect(self):
        row_id = await db.log_activity(
            event_type="connection", service="telnet",
            source_ip=self._source_ip, source_port=self._source_port,
            details="New Telnet connection", success=True,
        )
        self._transport.write(TELNET_NEGOTIATE)
        self._write(MOTD + TELNET_BANNER + "\r\nlogin: ")
        self._state = _TelnetState.AUTH_USER
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                "event_type": "connection", "service": "telnet",
                "source_ip": self._source_ip, "source_port": self._source_port,
                "details": "New Telnet connection", "success": True, "raw_data": None,
            },
        })

    async def _handle_line(self, line: str):
        if self._state == _TelnetState.AUTH_USER:
            self._username = line
            self._write("Password: ")
            self._state = _TelnetState.AUTH_PASS

        elif self._state == _TelnetState.AUTH_PASS:
            password = line
            row_id = await db.log_activity(
                event_type="authentication", service="telnet",
                source_ip=self._source_ip, source_port=self._source_port,
                details=f"Login attempt with credentials {self._username}:{password}",
                success=False,
                raw_data={"username": self._username, "password": password},
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "authentication", "service": "telnet",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"Login attempt with credentials {self._username}:{password}",
                    "success": False, "raw_data": None,
                },
            })
            self._fail_count += 1
            if self._fail_count < 3:
                # First attempt always fails; second attempt succeeds to keep them engaged
                self._write("\r\nLogin incorrect\r\n\r\nlogin: ")
                self._state = _TelnetState.AUTH_USER
            else:
                # 3rd attempt: let them in to capture shell activity
                self._fail_count = 0
                self._write(f"\r\nLast login: Mon Jan 15 10:23:01 2024 from 10.0.0.1\r\n")
                self._write(f"root@ubuntu-server:~# ")
                self._state = _TelnetState.SHELL

        elif self._state == _TelnetState.SHELL:
            if not line:
                self._write("root@ubuntu-server:~# ")
                return
            row_id = await db.log_activity(
                event_type="command", service="telnet",
                source_ip=self._source_ip, source_port=self._source_port,
                details=f"Executed command: {line}", success=True,
                raw_data={"command": line},
            )
            await self._emit({
                "event": "activity_log",
                "data": {
                    "id": row_id, "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "command", "service": "telnet",
                    "source_ip": self._source_ip, "source_port": self._source_port,
                    "details": f"Executed command: {line}", "success": True, "raw_data": None,
                },
            })
            if line in ("exit", "logout"):
                self._write("logout\r\n")
                self._transport.close()
                return
            resp = FAKE_SHELL_RESPONSES.get(line, f"-bash: {line}: command not found\r\n")
            self._write(resp + "root@ubuntu-server:~# ")


class TelnetHoneypot(BaseHoneypotService):
    service_id = "telnet"
    port       = TELNET_PORT

    async def start_server(self) -> None:
        loop    = asyncio.get_event_loop()
        emit_fn = self.emit
        self._server = await loop.create_server(
            lambda: TelnetProtocol(emit_fn), "0.0.0.0", self.port
        )
