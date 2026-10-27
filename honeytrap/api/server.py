"""FastAPI application factory for HoneyTrap."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from honeytrap.analysis.geo import GeoIPLookup
from honeytrap.analysis.ioc_extractor import IOCExtractor
from honeytrap.analysis.mitre import MITREMapper
from honeytrap.api.routes import create_router
from honeytrap.api.websocket import ConnectionManager
from honeytrap.events import EventBus, HoneypotEvent
from honeytrap.store import Store

logger = logging.getLogger(__name__)


def create_app(
    config: Any,
    event_bus: EventBus,
    store: Store,
    mitre: MITREMapper,
    ioc_extractor: IOCExtractor,
    geo: GeoIPLookup,
) -> FastAPI:
    """Create and configure the FastAPI HoneyTrap application."""
    app = FastAPI(
        title="HoneyTrap API",
        description="Multi-Protocol Honeypot Network API and Real-Time Event Stream",
        version="1.0.0",
    )

    # CORS configuration
    cors_origins = getattr(config.api, "cors_origins", ["*"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # WebSocket connection manager
    ws_manager = ConnectionManager()

    # Wire event bus to push events to WebSocket clients
    async def _broadcast_to_ws(event: HoneypotEvent) -> None:
        try:
            await ws_manager.broadcast(event.to_dict())
        except Exception as exc:
            logger.debug("Error broadcasting to WS: %s", exc)

    event_bus.subscribe(_broadcast_to_ws)

    # WebSocket endpoint
    @app.websocket("/ws/events")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await ws_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive; accept any incoming ping/message
                _ = await websocket.receive_text()
        except WebSocketDisconnect:
            await ws_manager.disconnect(websocket)
        except Exception:
            await ws_manager.disconnect(websocket)

    # Mount API routes
    router = create_router(
        store=store,
        mitre=mitre,
        ioc_extractor=ioc_extractor,
        geo=geo,
        sensor_id=config.sensor_id,
        data_dir=config.data_dir,
    )
    app.include_router(router)

    # Static assets and frontend SPA serving
    frontend_dir = Path("frontend")
    if not frontend_dir.is_dir():
        # Fallback to absolute or relative
        frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"

    if frontend_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

        @app.get("/")
        async def serve_index() -> FileResponse:
            index_file = frontend_dir / "index.html"
            if index_file.is_file():
                return FileResponse(str(index_file))
            return FileResponse(str(frontend_dir / "index.html"))

    return app
