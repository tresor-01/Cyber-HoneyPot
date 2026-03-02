"""
SSH Honeypot  —  medium-interaction
Uses asyncssh to present a realistic SSH-2 server.
Captures: banner grabs, every authentication attempt (user + password),
and all commands typed in the fake interactive shell.
"""

from __future__ import annotations
import asyncio
import asyncssh
import logging
import os
from datetime import datetime

import database as db
from config import SSH_PORT, SSH_BANNER
from services import BaseHoneypotService

logger = logging.getLogger(__name__)

# ── Fake file-system responses ─────────────────────────────────────────────────
FAKE_RESPONSES: dict[str, str] = {
    "ls":               "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n",
    "ls -la":           "total 68\r\ndrwxr-xr-x  20 root root 4096 Jan  1 00:00 .\r\ndrwxr-xr-x  20 root root 4096 Jan  1 00:00 ..\r\ndrwxr-xr-x   2 root root 4096 Jan  1 00:00 bin\r\n-rw-r--r--   1 root root  235 Jan  1 00:00 .bashrc\r\n",
    "pwd":              "/root\r\n",
    "whoami":           "root\r\n",
    "id":               "uid=0(root) gid=0(root) groups=0(root)\r\n",
    "uname -a":         "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n",
    "cat /etc/passwd":  "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n...\r\n",
    "cat /etc/shadow":  "cat: /etc/shadow: Permission denied\r\n",
    "ifconfig":         "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\r\n",
    "ip a":             "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\r\n    inet 192.168.1.100/24\r\n",
    "ps aux":           "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\nroot         1  0.0  0.1 167936 11320 ?        Ss   00:00   0:03 /sbin/init\r\nroot       456  0.0  0.0  72300  7140 ?        Ss   00:00   0:00 /usr/sbin/sshd\r\n",
    "netstat -an":      "Active Internet connections (servers and established)\r\nProto Recv-Q Send-Q Local Address           Foreign Address         State\r\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n",
    "history":          "    1  ls\r\n    2  whoami\r\n    3  uname -a\r\n",
    "exit":             "",
    "logout":          "",
}


class FakeSSHServerSession(asyncssh.SSHServerSession):
    def __init__(self, source_ip: str, source_port: int, emit_fn):
        self._source_ip   = source_ip
        self._source_port = source_port
        self._emit        = emit_fn
        self._chan         = None
        self._buf          = ""

    def connection_made(self, chan):
        self._chan = chan
        self._send_prompt()

    def _send_prompt(self):
        self._chan.write("\r\nroot@ubuntu-server:~# ")

    def data_received(self, data: str, datatype):
        self._buf += data
        if "\n" in self._buf or "\r" in self._buf:
            cmd = self._buf.strip().replace("\r", "").replace("\n", "")
            self._buf = ""
            asyncio.ensure_future(self._handle_command(cmd))

    async def _handle_command(self, cmd: str):
        if not cmd:
            self._send_prompt()
            return

        row_id = await db.log_activity(
            event_type="command",
            service="ssh",
            source_ip=self._source_ip,
            source_port=self._source_port,
            details=f"Executed command: {cmd}",
            success=True,
            raw_data={"command": cmd},
        )

        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "command",
                "service": "ssh",
                "source_ip": self._source_ip,
                "source_port": self._source_port,
                "details": f"Executed command: {cmd}",
                "success": True,
                "raw_data": None,
            },
        })

        response = FAKE_RESPONSES.get(cmd, f"-bash: {cmd}: command not found\r\n")
        if cmd in ("exit", "logout"):
            self._chan.write("logout\r\n")
            self._chan.exit(0)
            return
        self._chan.write(response)
        self._send_prompt()

    def eof_received(self):
        pass


class FakeSSHServer(asyncssh.SSHServer):
    def __init__(self, emit_fn):
        super().__init__()
        self._emit = emit_fn
        self._source_ip   = ""
        self._source_port = 0

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        self._source_ip   = peer[0] if peer else "unknown"
        self._source_port = peer[1] if peer else 0
        asyncio.ensure_future(self._log_connection())

    async def _log_connection(self):
        row_id = await db.log_activity(
            event_type="connection",
            service="ssh",
            source_ip=self._source_ip,
            source_port=self._source_port,
            details="New SSH connection established",
            success=True,
        )
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "connection",
                "service": "ssh",
                "source_ip": self._source_ip,
                "source_port": self._source_port,
                "details": "New SSH connection established",
                "success": True,
                "raw_data": None,
            },
        })

    def connection_lost(self, exc):
        asyncio.ensure_future(
            db.log_activity(
                event_type="disconnection",
                service="ssh",
                source_ip=self._source_ip,
                source_port=self._source_port,
                details="SSH connection terminated",
                success=True,
            )
        )

    def begin_auth(self, username: str) -> bool:
        return True  # Always require auth

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        asyncio.ensure_future(self._log_auth(username, password))
        return False  # Always deny — capture creds only

    async def _log_auth(self, username: str, password: str):
        row_id = await db.log_activity(
            event_type="authentication",
            service="ssh",
            source_ip=self._source_ip,
            source_port=self._source_port,
            details=f"Login attempt with credentials {username}:{password}",
            success=False,
            raw_data={"username": username, "password": password},
        )
        await self._emit({
            "event": "activity_log",
            "data": {
                "id": row_id,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": "authentication",
                "service": "ssh",
                "source_ip": self._source_ip,
                "source_port": self._source_port,
                "details": f"Login attempt with credentials {username}:{password}",
                "success": False,
                "raw_data": None,
            },
        })

    def session_requested(self) -> asyncssh.SSHServerSession:
        return FakeSSHServerSession(self._source_ip, self._source_port, self._emit)


class SSHHoneypot(BaseHoneypotService):
    service_id = "ssh"
    port       = SSH_PORT

    # asyncssh host key — auto-generated and cached
    _HOST_KEY_FILE = "ssh_host_key"

    def _get_or_create_key(self):
        if os.path.exists(self._HOST_KEY_FILE):
            return asyncssh.read_private_key(self._HOST_KEY_FILE)
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(self._HOST_KEY_FILE)
        return key

    async def start_server(self) -> None:
        host_key = self._get_or_create_key()
        emit_fn  = self.emit

        self._server = await asyncssh.create_server(
            lambda: FakeSSHServer(emit_fn),
            "",
            self.port,
            server_host_keys=[host_key],
            server_version=SSH_BANNER,
        )
