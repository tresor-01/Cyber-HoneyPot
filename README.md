# Cyber-HoneyPot

A full-stack cybersecurity honeypot system that lures attackers into realistic decoy services, captures their activity in real-time, and visualises everything on a live monitoring dashboard.

---

## What is a Honeypot?

A honeypot is a deliberately exposed system designed to attract attackers. Instead of defending a real system, it lets attackers interact freely with fake services — capturing credentials, commands, payloads, and attack patterns — while the attacker believes they have found a real target.

---

## Project Structure

```
Cyber-HoneyPot/
├── honeypot/               # React + TypeScript frontend dashboard
│   └── src/
│       ├── components/     # Dashboard, ServiceMonitor, ThreatFeed, ActivityLog
│       ├── hooks/          # useHoneypotWebSocket — real-time WS state
│       └── lib/            # REST API client (api.ts)
│
└── honeypot_backend/       # Python FastAPI backend
    ├── main.py             # API server, WebSocket broadcaster, service lifecycle
    ├── config.py           # Port / banner / threshold config (.env driven)
    ├── database.py         # Async SQLite via aiosqlite
    ├── models.py           # Pydantic API schemas
    ├── threat_detector.py  # Background threat analysis engine
    └── services/
        ├── ssh_service.py      # SSH-2 honeypot (asyncssh)
        ├── http_service.py     # HTTP honeypot (aiohttp)
        ├── ftp_service.py      # FTP honeypot
        ├── telnet_service.py   # Telnet honeypot
        ├── mysql_service.py    # MySQL handshake honeypot
        └── smtp_service.py     # SMTP / email honeypot
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18 · TypeScript · Vite |
| UI | Tailwind CSS · shadcn/ui (Radix UI) · Lucide icons |
| Real-time | WebSocket (native browser API) |
| Backend | Python 3.11+ · FastAPI · uvicorn |
| Honeypot services | asyncssh · aiohttp · asyncio TCP |
| Database | SQLite (aiosqlite) |
| System metrics | psutil |

---

## Honeypot Services

| Service | Standard Port | Alt Port* | What is captured |
|---------|:---:|:---:|---|
| SSH | 22 | 2222 | Every credential attempt, every shell command typed |
| HTTP | 80 | 8080 | All requests, form submissions on `/admin`, `/wp-admin`, `/phpmyadmin` |
| FTP | 21 | 2121 | Credentials, directory listings, file transfer attempts |
| Telnet | 23 | 2323 | Credentials, full interactive shell session commands |
| MySQL | 3306 | 3306 | Login handshake username extraction |
| SMTP | 25 | 2525 | AUTH credentials, sender/recipient addresses, full email body |

\* Alt ports require no root/admin. Enable with `USE_ALT_PORTS=true` in `.env`.

---

## Dashboard Features

- **Live status indicator** — shows WebSocket connection state (LIVE / CONNECTING / OFFLINE)
- **Stats overview** — total connections, blocked attacks, active threats, services running
- **Service Monitor** — per-service status, total connections, time since last activity
- **Activity Log** — real-time stream of every attacker action
- **Threat Feed** — auto-detected threats (brute force, port scan, injection, DDoS)
- **System Status** — live CPU, memory, and network I/O from the server running the backend
- **Start / Stop toggle** — shuts down all honeypot TCP listeners from the UI

---

## Threat Detection

The backend runs a continuous analysis engine that detects:

| Threat | Detection logic |
|---|---|
| **Brute Force** | ≥ 5 failed logins from the same IP within 60 seconds |
| **Port Scan** | Same IP hits ≥ 3 different services within 60 seconds |
| **Injection** | Commands / payloads containing SQL, path traversal, or XSS patterns |
| **DDoS** | ≥ 30 requests from a single IP within 60 seconds |

---

## Getting Started

### Prerequisites

- Node.js 18+
- Python 3.11+
- Git

### 1 — Clone

```bash
git clone https://github.com/your-username/Cyber-HoneyPot.git
cd Cyber-HoneyPot
```

### 2 — Backend setup

```bash
cd honeypot_backend

# Create virtual environment
python -m venv venv

# Activate
# Windows:
venv\Scripts\activate
# Linux / macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Configure ports in `honeypot_backend/.env`:

```env
# Use ports > 1024 (no admin/root required) — recommended for development
USE_ALT_PORTS=true
```

Start the backend:

```bash
# Standard ports (22, 80, 21, 23, 3306, 25) — requires Administrator / sudo
python main.py

# Alternate ports (2222, 8080, 2121, 2323, 3306, 2525) — no elevation needed
# USE_ALT_PORTS=true in .env, then:
python main.py
```

API available at `http://localhost:8000`.

### 3 — Frontend setup

```bash
cd honeypot

npm install
npm run dev
```

Dashboard available at `http://localhost:5173`.

---

## Configuration

### `honeypot_backend/.env`

```env
API_HOST=0.0.0.0
API_PORT=8000
CORS_ORIGINS=http://localhost:5173,http://localhost:8080
DB_PATH=honeypot.db

# Set true to use unprivileged ports (>1024)
USE_ALT_PORTS=false

# Threat detection tuning
BRUTE_FORCE_THRESHOLD=5
PORT_SCAN_THRESHOLD=3
BRUTE_WINDOW_SECONDS=60
```

### `honeypot/.env`

```env
# Backend URL consumed by the React frontend
VITE_API_URL=http://localhost:8000
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Honeypot + system stats |
| `GET` | `/api/logs?limit=50` | Recent activity log entries |
| `GET` | `/api/threats?limit=50` | Detected threat events |
| `GET` | `/api/services` | Per-service status and stats |
| `GET` | `/api/honeypot/status` | Current active state |
| `POST` | `/api/honeypot/start` | Start all honeypot services |
| `POST` | `/api/honeypot/stop` | Stop all honeypot services |
| `WS` | `/ws` | Real-time JSON event stream |

### WebSocket event types

```jsonc
{ "event": "initial_state",   "active": true, "logs": [...], "threats": [...], "services": [...] }
{ "event": "activity_log",    "data": { ...log entry } }
{ "event": "threat",          "data": { ...threat event } }
{ "event": "stats",           "data": { "honeypot": {...}, "system": {...} } }
{ "event": "honeypot_toggle", "active": false }
```

---

## Security Notice

> **This honeypot is intended to run in an isolated, intentionally exposed network segment.**

- Do **not** run on your primary machine as a production service.
- The fake services bind on well-known ports and will conflict with real services already using those ports.
- All captured credentials and payloads are stored in a local SQLite file (`honeypot.db`) — treat this file as sensitive.
- Never deploy without a firewall isolating the honeypot host from your internal network.

---

## License

See [LICENSE](LICENSE).

