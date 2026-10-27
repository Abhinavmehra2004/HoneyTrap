"""FastAPI route handlers for HoneyTrap."""

from __future__ import annotations

import json
import os
from typing import Any
from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from honeytrap.analysis.mitre import MITREMapper
from honeytrap.analysis.ioc_extractor import IOCExtractor
from honeytrap.analysis.geo import GeoIPLookup
from honeytrap.events import EventBus
from honeytrap.intel.blocklist import BlocklistExporter
from honeytrap.intel.stix_export import STIXExporter
from honeytrap.store import Store


def create_router(
    store: Store,
    mitre: MITREMapper,
    ioc_extractor: IOCExtractor,
    geo: GeoIPLookup,
    sensor_id: str = "honeytrap-01",
    data_dir: str = "data",
) -> APIRouter:
    router = APIRouter(prefix="/api")
    stix_exporter = STIXExporter(sensor_id=sensor_id)
    blocklist_exporter = BlocklistExporter()

    @router.get("/events")
    async def get_events(
        page: int = Query(1, ge=1),
        per_page: int = Query(50, ge=1, le=500),
        protocol: str | None = None,
        event_type: str | None = None,
        source_ip: str | None = None,
        session_id: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        search: str | None = None,
    ) -> dict[str, Any]:
        filters: dict[str, Any] = {}
        if protocol:
            filters["protocol"] = protocol
        if event_type:
            filters["event_type"] = event_type
        if source_ip:
            filters["source_ip"] = source_ip
        if session_id:
            filters["session_id"] = session_id
        if start_time:
            filters["start_time"] = start_time
        if end_time:
            filters["end_time"] = end_time
        if search:
            filters["search"] = search

        total = await store.count_events(filters)
        events = await store.get_events(filters, page=page, per_page=per_page)
        pages = (total + per_page - 1) // per_page if total > 0 else 1

        return {
            "events": events,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }

    @router.get("/sessions")
    async def get_sessions(
        page: int = Query(1, ge=1),
        per_page: int = Query(50, ge=1, le=500),
        protocol: str | None = None,
        source_ip: str | None = None,
    ) -> dict[str, Any]:
        total = await store.count_sessions(protocol=protocol, source_ip=source_ip)
        sessions = await store.get_sessions(page=page, per_page=per_page, protocol=protocol, source_ip=source_ip)
        pages = (total + per_page - 1) // per_page if total > 0 else 1
        return {
            "sessions": sessions,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }

    @router.get("/sessions/{session_id}")
    async def get_session_detail(session_id: str) -> dict[str, Any]:
        detail = await store.get_session_detail(session_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Session not found")

        # Check for asciicast recording
        cast_file = f"{data_dir}/sessions/{session_id}.cast"
        if os.path.exists(cast_file):
            try:
                with open(cast_file, "r", encoding="utf-8") as f:
                    detail["asciicast"] = f.read()
            except Exception:
                detail["asciicast"] = None
        else:
            detail["asciicast"] = None

        return detail

    @router.get("/stats")
    async def get_stats() -> dict[str, Any]:
        return await store.get_stats()

    @router.get("/mitre")
    async def get_mitre_stats() -> list[dict[str, Any]]:
        return await store.get_mitre_stats()

    @router.get("/iocs")
    async def get_iocs(
        type: str | None = None,
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        return await store.get_iocs(ioc_type=type, limit=limit)

    @router.get("/attackers")
    async def get_top_attackers(limit: int = Query(20, ge=1, le=100)) -> list[dict[str, Any]]:
        return await store.get_top_attackers(limit=limit)

    @router.get("/export/stix")
    async def export_stix() -> JSONResponse:
        events = await store.get_events(page=1, per_page=100)
        iocs = await store.get_iocs(limit=100)
        mitre_stats = await store.get_mitre_stats()
        bundle = stix_exporter.export_bundle(events, iocs, mitre_stats)
        return JSONResponse(
            content=bundle,
            headers={"Content-Disposition": 'attachment; filename="honeytrap-stix2.json"'},
        )

    @router.get("/export/blocklist")
    async def export_blocklist(
        format: str = Query("plaintext", regex="^(iptables|nginx|csv|plaintext|txt)$")
    ) -> Response:
        attackers = await store.get_top_attackers(limit=500)
        fmt = format.lower()

        if fmt == "iptables":
            content = blocklist_exporter.export_iptables(attackers)
            return PlainTextResponse(
                content,
                headers={"Content-Disposition": 'attachment; filename="honeytrap-iptables.sh"'},
            )
        elif fmt == "nginx":
            content = blocklist_exporter.export_nginx(attackers)
            return PlainTextResponse(
                content,
                headers={"Content-Disposition": 'attachment; filename="honeytrap-blocklist.conf"'},
            )
        elif fmt == "csv":
            content = blocklist_exporter.export_csv(attackers)
            return Response(
                content=content,
                media_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="honeytrap-attackers.csv"'},
            )
        else:
            content = blocklist_exporter.export_plaintext(attackers)
            return PlainTextResponse(
                content,
                headers={"Content-Disposition": 'attachment; filename="honeytrap-blocklist.txt"'},
            )

    return router
