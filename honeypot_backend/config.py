"""
Honeypot configuration.

Port note:
  Ports < 1024 require elevated privileges.
  On Windows: run as Administrator.
  On Linux:   sudo python main.py  OR  sudo setcap cap_net_bind_service+ep $(which python)
  For rootless testing, set USE_ALT_PORTS=true in .env to use ports > 1024.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── API Server ────────────────────────────────────────────────────────────────
API_HOST = os.getenv("API_HOST", "127.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

# ── Frontend origin (CORS) ────────────────────────────────────────────────────
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")

# ── SQLite database path ──────────────────────────────────────────────────────
DB_PATH = os.getenv("DB_PATH", "honeypot.db")

# ── Alternate unprivileged ports (USE_ALT_PORTS=true) ─────────────────────────
USE_ALT_PORTS = os.getenv("USE_ALT_PORTS", "false").lower() == "true"

def _port(standard: int, alt: int) -> int:
    return alt if USE_ALT_PORTS else standard

# ── Honeypot service bind ports ───────────────────────────────────────────────
SSH_PORT    = int(os.getenv("SSH_PORT",    str(_port(22,   2222))))
HTTP_PORT   = int(os.getenv("HTTP_PORT",   str(_port(80,   8080))))
FTP_PORT    = int(os.getenv("FTP_PORT",    str(_port(21,   2121))))
TELNET_PORT = int(os.getenv("TELNET_PORT", str(_port(23,   2323))))
MYSQL_PORT  = int(os.getenv("MYSQL_PORT",  str(_port(3306, 3306))))
SMTP_PORT   = int(os.getenv("SMTP_PORT",   str(_port(25,   2525))))
RDP_PORT    = int(os.getenv("RDP_PORT",    str(_port(3389, 3389))))
VNC_PORT    = int(os.getenv("VNC_PORT",    str(_port(5900, 5900))))
REDIS_PORT  = int(os.getenv("REDIS_PORT",  str(_port(6379, 6379))))
PGSQL_PORT  = int(os.getenv("PGSQL_PORT",  str(_port(5432, 5432))))

# ── Fake server banners ────────────────────────────────────────────────────────
SSH_BANNER    = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
HTTP_SERVER   = "Apache/2.4.58 (Ubuntu)"
FTP_BANNER    = "220 (vsFTPd 3.0.5)"
TELNET_BANNER = "\r\nUbuntu 22.04.3 LTS\r\n"
MYSQL_VERSION = "8.0.36-0ubuntu0.22.04.1"
SMTP_BANNER   = "220 mail.corp-internal.local ESMTP Postfix (Ubuntu)"
REDIS_VERSION = "7.2.4"
PGSQL_VERSION = "14.11"

# ── Threat detection thresholds ───────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))   # failed auths
PORT_SCAN_THRESHOLD   = int(os.getenv("PORT_SCAN_THRESHOLD",   "3"))   # services hit
BRUTE_WINDOW_SECONDS  = int(os.getenv("BRUTE_WINDOW_SECONDS",  "60"))  # time window
