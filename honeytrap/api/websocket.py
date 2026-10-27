"""WebSocket Connection Manager for HoneyTrap real-time event streaming."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active browser WebSocket clients for live event streaming."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.debug("WebSocket client connected. Active: %d", len(self.active_connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.debug("WebSocket client disconnected. Active: %d", len(self.active_connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast JSON payload to all active clients."""
        async with self._lock:
            conns = list(self.active_connections)

        if not conns:
            return

        payload_str = json.dumps(message)
        dead: list[WebSocket] = []

        for conn in conns:
            try:
                await conn.send_text(payload_str)
            except Exception:
                dead.append(conn)

        if dead:
            async with self._lock:
                for d in dead:
                    if d in self.active_connections:
                        self.active_connections.remove(d)
