# Cyber-HoneyPot Backend

FastAPI + asyncio backend that runs **real honeypot services** and streams events
to the React dashboard over WebSocket.

## Architecture

```
honeypot_backend/
├── main.py              # FastAPI app, WebSocket broadcaster, service lifecycle
├── config.py            # Port config, banners, thresholds (.env driven)
├── database.py          # Async SQLite helpers (aiosqlite)
├── models.py            # Pydantic API schemas
├── threat_detector.py   # Background threat analysis engine
├── requirements.txt
├── .env                 # Your local config — create this manually (see Quick Start)
└── services/
    ├── ssh_service.py   # SSH-2 honeypot (asyncssh)
    ├── http_service.py  # HTTP honeypot with fake admin/wp-admin/phpmyadmin
    ├── ftp_service.py   # FTP honeypot (asyncio TCP)
    ├── telnet_service.py# Telnet honeypot with interactive fake shell
    ├── mysql_service.py # MySQL handshake honeypot
    └── smtp_service.py  # SMTP honeypot with full email capture
```

## Quick Start

### 1. Create a virtual environment

```bash
cd honeypot_backend
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Create your `.env` file

> **The `.env` file is not included in the repository** (it is gitignored).
> You must create it yourself before running the backend.

The easiest way is to copy the provided example template:

```bash
# Windows (PowerShell)
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

Then open `.env` and edit any values you want to change.  
The full list of variables and what they do:

```env
# ── API server ────────────────────────────────────────────────────────────────
API_HOST=0.0.0.0
API_PORT=8000

# ── CORS — comma-separated list of your frontend origins ─────────────────────
CORS_ORIGINS=http://localhost:5173,http://localhost:8080

# ── Database — path to the SQLite file that will be created automatically ─────
DB_PATH=honeypot.db

# ── Unprivileged port mode ────────────────────────────────────────────────────
# Set to true  → uses ports 2222, 8080, 2121, 2323, 3306, 2525  (no root needed)
# Set to false → uses ports   22,   80,   21,   23, 3306,   25  (requires admin/sudo)
USE_ALT_PORTS=false

# ── Individual port overrides (optional — remove # to activate) ───────────────
# SSH_PORT=22
# HTTP_PORT=80
# FTP_PORT=21
# TELNET_PORT=23
# MYSQL_PORT=3306
# SMTP_PORT=25

# ── Threat detection tuning ───────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD=5     # failed logins from one IP before brute-force alert
PORT_SCAN_THRESHOLD=3       # services hit by one IP before port-scan alert
BRUTE_WINDOW_SECONDS=60     # time window (seconds) for the above counts
```

> **Tip for development / first-time setup:** set `USE_ALT_PORTS=true`.
> This lets the backend run without Administrator or `sudo` privileges because
> all services use ports above 1024.

### 4. Configure ports

Edit `.env`.  Two modes:

| Mode | Ports used | Requires |
|------|-----------|---------|
| Standard (default) | 22, 80, 21, 23, 3306, 25 | Administrator / root |
| Alternate | 2222, 8080, 2121, 2323, 3306, 2525 | Normal user |

For **rootless testing** set `USE_ALT_PORTS=true` in `.env`.

### 5. Run

**Windows (Administrator) / Linux (sudo):**
```bash
python main.py
```

**Development / rootless:**
```bash
# .env: USE_ALT_PORTS=true
python main.py
```

The API will be at `http://localhost:8000`.

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/stats` | Honeypot + system stats |
| GET | `/api/logs?limit=50` | Activity log entries |
| GET | `/api/threats?limit=50` | Detected threat events |
| GET | `/api/services` | Per-service status |
| GET | `/api/honeypot/status` | Current active state |
| POST | `/api/honeypot/start` | Start all services |
| POST | `/api/honeypot/stop` | Stop all services |
| WS | `/ws` | Real-time event stream |

## WebSocket Events

All events are JSON with an `event` field:

```jsonc
{ "event": "initial_state",  "active": true, "logs": [...], "threats": [...], "services": [...] }
{ "event": "activity_log",   "data": { ...ActivityLog } }
{ "event": "threat",         "data": { ...Threat } }
{ "event": "service_update", "data": { ...ServiceStat } }
{ "event": "stats",          "data": { honeypot: {...}, system: {...} } }
{ "event": "honeypot_toggle","active": false }
```

## Security Note

This honeypot is intended to run in an **isolated, intentionally exposed network
segment**. Do **not** run it as your primary machine's web server. The fake
services bind on standard ports and will conflict with existing services.
