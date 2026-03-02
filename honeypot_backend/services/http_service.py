"""
HTTP Honeypot  —  medium-interaction
Uses aiohttp to serve a realistic-looking vulnerable web server.
Captures: all HTTP requests, form submissions (credentials), path probing.
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime

from aiohttp import web

import database as db
from config import HTTP_PORT, HTTP_SERVER
from services import BaseHoneypotService

logger = logging.getLogger(__name__)

# ── Fake HTML pages ────────────────────────────────────────────────────────────

_ADMIN_LOGIN = """<!DOCTYPE html>
<html><head><title>Admin Panel</title></head>
<body style="background:#1a1a2e;color:#eee;font-family:sans-serif;display:flex;justify-content:center;padding-top:100px">
<form method="POST" style="background:#16213e;padding:30px;border-radius:8px;min-width:300px">
  <h2 style="color:#00d4ff">Admin Login</h2>
  <input name="username" placeholder="Username" style="display:block;width:100%;margin:8px 0;padding:8px;background:#0f3460;color:#eee;border:1px solid #00d4ff;border-radius:4px"><br>
  <input name="password" type="password" placeholder="Password" style="display:block;width:100%;margin:8px 0;padding:8px;background:#0f3460;color:#eee;border:1px solid #00d4ff;border-radius:4px"><br>
  <button type="submit" style="width:100%;padding:10px;background:#00d4ff;color:#000;border:none;border-radius:4px;cursor:pointer">Login</button>
</form></body></html>"""

_WP_LOGIN = """<!DOCTYPE html>
<html><head><title>WordPress Login</title></head>
<body style="background:#f1f1f1;font-family:sans-serif;display:flex;justify-content:center;padding-top:60px">
<div style="background:#fff;padding:30px;border-radius:4px;min-width:320px;box-shadow:0 1px 3px rgba(0,0,0,.2)">
  <h1 style="text-align:center">WordPress</h1>
  <form method="POST">
    <label>Username</label><br>
    <input name="log" style="width:100%;padding:8px;margin:6px 0"><br>
    <label>Password</label><br>
    <input name="pwd" type="password" style="width:100%;padding:8px;margin:6px 0"><br>
    <button type="submit" style="width:100%;padding:10px;background:#0073aa;color:#fff;border:none;cursor:pointer;margin-top:10px">Log In</button>
  </form>
</div></body></html>"""

_PHPMYADMIN = """<!DOCTYPE html>
<html><head><title>phpMyAdmin</title></head>
<body style="background:#fff;font-family:sans-serif;display:flex;justify-content:center;padding-top:80px">
<div style="border:1px solid #ccc;padding:30px;min-width:300px">
  <h2>phpMyAdmin</h2>
  <form method="POST">
    <label>Username:</label><br>
    <input name="pma_username" style="width:100%;margin:6px 0;padding:6px"><br>
    <label>Password:</label><br>
    <input name="pma_password" type="password" style="width:100%;margin:6px 0;padding:6px"><br>
    <button type="submit" style="padding:8px 20px;margin-top:8px">Go</button>
  </form>
</div></body></html>"""


class HTTPHoneypot(BaseHoneypotService):
    service_id = "http"
    port       = HTTP_PORT

    def __init__(self):
        super().__init__()
        self._runner: web.AppRunner | None = None

    async def _log_and_emit(self, request: web.Request, details: str,
                             event_type: str = "connection", success: bool = False,
                             raw_data: dict | None = None):
        ip   = request.remote or "unknown"
        port = request.transport.get_extra_info("peername", (None, 0))[1] if request.transport else 0
        row_id = await db.log_activity(
            event_type=event_type,
            service="http",
            source_ip=ip,
            source_port=port,
            details=details,
            success=success,
            raw_data=raw_data,
        )
        await self.emit({
            "event": "activity_log",
            "data": {
                "id": row_id,
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "service": "http",
                "source_ip": ip,
                "source_port": port,
                "details": details,
                "success": success,
                "raw_data": None,
            },
        })

    # ── Route handlers ─────────────────────────────────────────────────────────

    async def _handle_root(self, request: web.Request) -> web.Response:
        await self._log_and_emit(request, f"HTTP {request.method} {request.path}")
        headers = {"Server": HTTP_SERVER, "X-Powered-By": "PHP/8.1.27"}
        raise web.HTTPFound("/admin", headers=headers)

    async def _handle_admin(self, request: web.Request) -> web.Response:
        headers = {"Server": HTTP_SERVER}
        if request.method == "POST":
            data = await request.post()
            user = data.get("username", "")
            pw   = data.get("password", "")
            await self._log_and_emit(
                request,
                f"Admin login attempt: {user}:{pw}",
                event_type="authentication",
                success=False,
                raw_data={"username": user, "password": pw, "path": "/admin"},
            )
            return web.Response(
                text=_ADMIN_LOGIN.replace("</form>", "<p style='color:red'>Invalid credentials</p></form>"),
                content_type="text/html",
                headers=headers,
            )
        await self._log_and_emit(request, "GET /admin — admin panel probed",
                                  event_type="file_access")
        return web.Response(text=_ADMIN_LOGIN, content_type="text/html", headers=headers)

    async def _handle_wp_admin(self, request: web.Request) -> web.Response:
        headers = {"Server": HTTP_SERVER, "X-Powered-By": "PHP/8.1.27"}
        if request.method == "POST":
            data = await request.post()
            user = data.get("log", "")
            pw   = data.get("pwd", "")
            await self._log_and_emit(
                request,
                f"WordPress login attempt: {user}:{pw}",
                event_type="authentication",
                success=False,
                raw_data={"username": user, "password": pw, "path": "/wp-admin"},
            )
        else:
            await self._log_and_emit(request, "GET /wp-admin — WordPress probed",
                                      event_type="file_access")
        return web.Response(text=_WP_LOGIN, content_type="text/html", headers=headers)

    async def _handle_phpmyadmin(self, request: web.Request) -> web.Response:
        headers = {"Server": HTTP_SERVER, "X-Powered-By": "PHP/8.1.27"}
        if request.method == "POST":
            data = await request.post()
            user = data.get("pma_username", "")
            pw   = data.get("pma_password", "")
            await self._log_and_emit(
                request,
                f"phpMyAdmin login attempt: {user}:{pw}",
                event_type="authentication",
                success=False,
                raw_data={"username": user, "password": pw, "path": "/phpmyadmin"},
            )
        else:
            await self._log_and_emit(request, "GET /phpmyadmin — DB admin probed",
                                      event_type="file_access")
        return web.Response(text=_PHPMYADMIN, content_type="text/html", headers=headers)

    async def _handle_catch_all(self, request: web.Request) -> web.Response:
        await self._log_and_emit(
            request,
            f"HTTP {request.method} {request.path} — path probed",
            event_type="file_access",
        )
        return web.Response(status=404, text="Not Found",
                            headers={"Server": HTTP_SERVER})

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def start_server(self) -> None:
        app = web.Application()
        app.router.add_get("/",            self._handle_root)
        app.router.add_route("*", "/admin",       self._handle_admin)
        app.router.add_route("*", "/admin/",      self._handle_admin)
        app.router.add_route("*", "/wp-admin",    self._handle_wp_admin)
        app.router.add_route("*", "/wp-admin/",   self._handle_wp_admin)
        app.router.add_route("*", "/phpmyadmin",  self._handle_phpmyadmin)
        app.router.add_route("*", "/phpmyadmin/", self._handle_phpmyadmin)
        app.router.add_route("*", "/{path_info:.*}", self._handle_catch_all)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self.port)
        await site.start()
        # aiohttp doesn't expose an asyncio.AbstractServer directly,
        # set a sentinel so stop() knows to clean up differently
        self._server = True  # type: ignore[assignment]

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._running = False
        logger.info("[HTTP] Stopped")
