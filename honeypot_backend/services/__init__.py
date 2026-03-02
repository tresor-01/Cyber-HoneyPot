"""Base honeypot service."""

from __future__ import annotations
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable, Awaitable

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class BaseHoneypotService(ABC):
    """
    Abstract base class for all honeypot services.

    Subclasses implement `start_server()` which should start an asyncio
    server and store it in `self._server`.  The base class provides
    lifecycle management (start / stop) and a reference hook so services
    can emit events to the WebSocket broadcaster.
    """

    service_id: str = ""
    port: int = 0

    def __init__(self) -> None:
        self._server: asyncio.AbstractServer | None = None
        self._running = False
        # Injected by ServiceManager after instantiation
        self._emit: Callable[[dict], Awaitable[None]] | None = None

    # ── Public lifecycle ───────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        try:
            await self.start_server()
            self._running = True
            logger.info("[%s] Listening on port %d", self.service_id.upper(), self.port)
        except OSError as exc:
            logger.error(
                "[%s] Failed to bind port %d: %s — "
                "try USE_ALT_PORTS=true or run as Administrator/root",
                self.service_id.upper(),
                self.port,
                exc,
            )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False
        logger.info("[%s] Stopped", self.service_id.upper())

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Event emission ─────────────────────────────────────────────────────────

    async def emit(self, payload: dict) -> None:
        if self._emit:
            try:
                await self._emit(payload)
            except Exception:
                pass

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    async def start_server(self) -> None:
        """Start the underlying TCP/asyncssh server and set self._server."""
