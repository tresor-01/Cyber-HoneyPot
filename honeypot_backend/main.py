"""
Cybersecurity Honeypot — FastAPI backend

Run with:
  python main.py
  -- or --
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Endpoints
  GET  /api/stats            — honeypot + system stats
  GET  /api/logs             — recent activity logs   (?limit=50&offset=0)
  GET  /api/threats          — recent threat events   (?limit=50&offset=0)
  GET  /api/services         — per-service stats + live status
  POST /api/honeypot/start   — start all honeypot services
  POST /api/honeypot/stop    — stop all honeypot services
  WS   /ws                   — real-time event stream (JSON)
"""

from __future__ import annotations
import asyncio
import json
import logging
import sys

import psutil
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

import database as db
from config import (
    API_HOST, API_PORT, CORS_ORIGINS,
    SSH_PORT, HTTP_PORT, FTP_PORT, TELNET_PORT, MYSQL_PORT, SMTP_PORT,
    RDP_PORT, VNC_PORT, REDIS_PORT, PGSQL_PORT,
)
from models import (
    ActivityLogOut, ThreatOut, ServiceStatOut,
    SummaryStats, SystemStats, FullStats,
)
from services.ssh_service        import SSHHoneypot
from services.http_service       import HTTPHoneypot
from services.ftp_service        import FTPHoneypot
from services.telnet_service     import TelnetHoneypot
from services.mysql_service      import MySQLHoneypot
from services.smtp_service       import SMTPHoneypot
from services.rdp_service        import RDPHoneypot
from services.vnc_service        import VNCHoneypot
from services.redis_service      import RedisHoneypot
from services.postgresql_service import PostgreSQLHoneypot
from threat_detector             import ThreatDetector

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream = sys.stdout,
)
logger = logging.getLogger(__name__)

# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(title="Cyber HoneyPot API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins     = CORS_ORIGINS,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── WebSocket manager ──────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        logger.info("WS client connected (%d total)", len(self._connections))

    def disconnect(self, ws: WebSocket):
        self._connections.discard(ws) if hasattr(self._connections, "discard") else None
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast(self, payload: dict):
        if not self._connections:
            return
        text = json.dumps(payload)
        dead = []
        for ws in list(self._connections):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()

# ── Service manager ────────────────────────────────────────────────────────────

_SERVICE_PORTS = {
    "ssh":        SSH_PORT,
    "http":       HTTP_PORT,
    "ftp":        FTP_PORT,
    "telnet":     TELNET_PORT,
    "mysql":      MYSQL_PORT,
    "smtp":       SMTP_PORT,
    "rdp":        RDP_PORT,
    "vnc":        VNC_PORT,
    "redis":      REDIS_PORT,
    "postgresql": PGSQL_PORT,
}

_services: dict[str, object] = {}
_detector: ThreatDetector | None = None
_honeypot_active = False


async def _broadcast(payload: dict):
    await manager.broadcast(payload)


async def _start_all_services():
    global _honeypot_active, _detector
    ssh        = SSHHoneypot()
    http       = HTTPHoneypot()
    ftp        = FTPHoneypot()
    telnet     = TelnetHoneypot()
    mysql      = MySQLHoneypot()
    smtp       = SMTPHoneypot()
    rdp        = RDPHoneypot()
    vnc        = VNCHoneypot()
    redis      = RedisHoneypot()
    postgresql = PostgreSQLHoneypot()

    for svc in (ssh, http, ftp, telnet, mysql, smtp, rdp, vnc, redis, postgresql):
        svc._emit = _broadcast
        await svc.start()
        _services[svc.service_id] = svc

    _detector = ThreatDetector(_broadcast)
    await _detector.start()
    _honeypot_active = True
    logger.info("All honeypot services started")

    # Broadcast toggle event
    await manager.broadcast({"event": "honeypot_toggle", "active": True})


async def _stop_all_services():
    global _honeypot_active, _detector
    for svc in list(_services.values()):
        await svc.stop()
    _services.clear()
    if _detector:
        await _detector.stop()
        _detector = None
    _honeypot_active = False
    await manager.broadcast({"event": "honeypot_toggle", "active": False})
    logger.info("All honeypot services stopped")


# ── Startup / shutdown ─────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    await db.init_db()
    await _start_all_services()
    # Periodic stats push every 5 seconds
    asyncio.ensure_future(_stats_pusher())


async def _stats_pusher():
    """Push system + honeypot stats to WebSocket clients every 5 seconds."""
    net_before = psutil.net_io_counters()
    while True:
        await asyncio.sleep(5)
        try:
            honeypot_stats   = await db.get_summary_stats()
            honeypot_stats["services_running"] = len(_services)
            cpu              = psutil.cpu_percent(interval=None)
            mem              = psutil.virtual_memory().percent
            net_after        = psutil.net_io_counters()
            await manager.broadcast({
                "event": "stats",
                "data": {
                    "honeypot": honeypot_stats,
                    "system": {
                        "cpu_percent":        cpu,
                        "memory_percent":     mem,
                        "network_bytes_sent": net_after.bytes_sent - net_before.bytes_sent,
                        "network_bytes_recv": net_after.bytes_recv - net_before.bytes_recv,
                    },
                },
            })
            net_before = net_after
        except Exception as exc:
            logger.warning("Stats pusher error: %s", exc)


@app.on_event("shutdown")
async def shutdown():
    await _stop_all_services()


# ── REST endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    honeypot_stats = await db.get_summary_stats()
    honeypot_stats["services_running"] = len(_services)
    cpu     = psutil.cpu_percent(interval=0.1)
    mem     = psutil.virtual_memory().percent
    net     = psutil.net_io_counters()
    return {
        "honeypot": honeypot_stats,
        "system": {
            "cpu_percent":        cpu,
            "memory_percent":     mem,
            "network_bytes_sent": net.bytes_sent,
            "network_bytes_recv": net.bytes_recv,
        },
    }


@app.get("/api/logs")
async def get_logs(limit: int = 50, offset: int = 0):
    rows = await db.get_logs(limit=limit, offset=offset)
    return rows


@app.get("/api/threats")
async def get_threats(limit: int = 50, offset: int = 0):
    rows = await db.get_threats(limit=limit, offset=offset)
    return rows


@app.get("/api/services")
async def get_services():
    stats = await db.get_service_stats()
    result = []
    for row in stats:
        svc = _services.get(row["service_id"])
        running = svc.is_running if svc else False
        result.append({
            **row,
            "status": "active" if running else "inactive",
            "port":   _SERVICE_PORTS.get(row["service_id"], 0),
        })
    return result


@app.post("/api/honeypot/start")
async def start_honeypot():
    if not _honeypot_active:
        await _start_all_services()
    return {"active": True}


@app.post("/api/honeypot/stop")
async def stop_honeypot():
    if _honeypot_active:
        await _stop_all_services()
    return {"active": False}


@app.get("/api/honeypot/status")
async def honeypot_status():
    return {"active": _honeypot_active}


# ── WebSocket endpoint ─────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send current state immediately on connect
        logs     = await db.get_logs(limit=20)
        threats  = await db.get_threats(limit=10)
        svcs     = await db.get_service_stats()
        wait_data = {
            "event":    "initial_state",
            "active":   _honeypot_active,
            "logs":     logs,
            "threats":  threats,
            "services": [
                {
                    **s,
                    "status": "active" if (
                        _services.get(s["service_id"]) and
                        _services[s["service_id"]].is_running
                    ) else "inactive",
                    "port": _SERVICE_PORTS.get(s["service_id"], 0),
                }
                for s in svcs
            ],
        }
        await websocket.send_text(json.dumps(wait_data))

        # Keep connection alive (client pings)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("WS client disconnected")
    except Exception as exc:
        logger.warning("WS error: %s", exc)
        manager.disconnect(websocket)


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("main:app", host=API_HOST, port=API_PORT, reload=False)
