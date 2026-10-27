"""Abstract Base Class for HoneyTrap Honeypots."""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from honeytrap.events import EventBus, EventType, HoneypotEvent


class BaseHoneypot(ABC):
    """Base class for all honeypot protocol implementations."""

    def __init__(self, config: Any, event_bus: EventBus, sensor_id: str = "honeytrap-01") -> None:
        self.config = config
        self.event_bus = event_bus
        self.sensor_id = sensor_id
        self.sessions: dict[str, dict[str, Any]] = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    async def start(self) -> None:
        """Start listening for incoming attacker connections."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully stop the honeypot listener."""
        ...

    async def create_session(self, source_ip: str, source_port: int, protocol: str) -> str:
        """Track new session and emit SESSION_START event."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        self.sessions[session_id] = {
            "id": session_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "protocol": protocol,
            "start_time": now,
        }

        await self.emit_event(
            session_id=session_id,
            event_type=EventType.SESSION_START,
            source_ip=source_ip,
            source_port=source_port,
            protocol=protocol,
            data={"message": f"New {protocol.upper()} connection established"},
        )
        return session_id

    async def end_session(self, session_id: str) -> None:
        """Clean up session and emit SESSION_END event."""
        session_data = self.sessions.pop(session_id, None)
        if session_data:
            await self.emit_event(
                session_id=session_id,
                event_type=EventType.SESSION_END,
                source_ip=session_data["source_ip"],
                source_port=session_data["source_port"],
                protocol=session_data["protocol"],
                data={"message": f"{session_data['protocol'].upper()} session closed"},
            )

    async def emit_event(
        self,
        session_id: str,
        event_type: EventType,
        source_ip: str,
        source_port: int,
        protocol: str,
        data: dict[str, Any],
    ) -> HoneypotEvent:
        """Create a HoneypotEvent and publish to the asyncio EventBus."""
        event = HoneypotEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            sensor_id=self.sensor_id,
            session_id=session_id,
            protocol=protocol,
            event_type=event_type,
            source_ip=source_ip,
            source_port=source_port,
            data=data,
        )
        await self.event_bus.publish(event)
        return event
