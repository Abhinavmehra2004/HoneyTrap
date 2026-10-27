"""
HoneyTrap Data Models.

Data models for sessions, events, indicators of compromise (IOCs),
and MITRE ATT&CK techniques.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from honeytrap.events import EventType, HoneypotEvent

logger = logging.getLogger(__name__)

# Event model matches HoneypotEvent
Event = HoneypotEvent


def _parse_datetime(val: Any) -> datetime:
    """Safely parse datetime from ISO string or datetime object."""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    return datetime.now(timezone.utc)


@dataclass
class Session:
    """Represents an attacker session across honeypot protocols."""
    id: str
    protocol: str  # ssh, http, ftp
    source_ip: str
    source_port: int
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None
    events_count: int = 0
    sensor_id: str = "honeytrap-01"
    geo: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.start_time = _parse_datetime(self.start_time)
        if self.end_time is not None:
            self.end_time = _parse_datetime(self.end_time)

    def to_dict(self) -> dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "id": self.id,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "events_count": self.events_count,
            "sensor_id": self.sensor_id,
            "geo": self.geo,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        """Create session from dictionary."""
        return cls(
            id=str(data["id"]),
            protocol=str(data["protocol"]),
            source_ip=str(data["source_ip"]),
            source_port=int(data["source_port"]),
            start_time=_parse_datetime(data.get("start_time")),
            end_time=_parse_datetime(data["end_time"]) if data.get("end_time") else None,
            events_count=int(data.get("events_count", 0)),
            sensor_id=str(data.get("sensor_id", "honeytrap-01")),
            geo=data.get("geo"),
        )


@dataclass
class IOC:
    """Represents an Indicator of Compromise extracted from attack traffic."""
    type: str  # e.g., 'ip', 'url', 'hash', 'user_agent', 'credential'
    value: str
    confidence: float = 1.0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_sessions: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.first_seen = _parse_datetime(self.first_seen)
        self.last_seen = _parse_datetime(self.last_seen)

    def to_dict(self) -> dict[str, Any]:
        """Convert IOC to dictionary."""
        return {
            "type": self.type,
            "value": self.value,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "source_sessions": self.source_sessions,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IOC:
        """Create IOC from dictionary."""
        return cls(
            type=str(data["type"]),
            value=str(data["value"]),
            confidence=float(data.get("confidence", 1.0)),
            first_seen=_parse_datetime(data.get("first_seen")),
            last_seen=_parse_datetime(data.get("last_seen")),
            source_sessions=list(data.get("source_sessions", [])),
        )


@dataclass
class MITRETechnique:
    """Represents an observed MITRE ATT&CK technique and aggregate detection count."""
    technique_id: str  # e.g., 'T1110.001'
    name: str  # e.g., 'Password Guessing'
    tactic: str  # e.g., 'Credential Access'
    count: int = 1
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        self.last_seen = _parse_datetime(self.last_seen)

    def to_dict(self) -> dict[str, Any]:
        """Convert MITRE technique to dictionary."""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "count": self.count,
            "last_seen": self.last_seen.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MITRETechnique:
        """Create MITRETechnique from dictionary."""
        return cls(
            technique_id=str(data["technique_id"]),
            name=str(data.get("name", "")),
            tactic=str(data.get("tactic", "")),
            count=int(data.get("count", 1)),
            last_seen=_parse_datetime(data.get("last_seen")),
        )


__all__ = [
    "EventType",
    "HoneypotEvent",
    "Event",
    "Session",
    "IOC",
    "MITRETechnique",
]
