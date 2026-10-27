"""IOC Extractor for HoneyTrap.

Extracts Indicators of Compromise (IPs, URLs, domains, credentials, user-agents)
from honeypot events with confidence scoring, filtering, and deduplication.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from honeytrap.events import EventType, HoneypotEvent
from honeytrap.models import IOC


@dataclass
class ExtractedIOC:
    """Extracted IOC with metadata matching tests."""
    type: str  # ip_address, url, domain, email, user_agent, credential_pair
    value: str
    confidence: float
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_sessions: list[str] = field(default_factory=list)
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if isinstance(self.first_seen, datetime) else str(self.first_seen),
            "last_seen": self.last_seen.isoformat() if isinstance(self.last_seen, datetime) else str(self.last_seen),
            "source_sessions": self.source_sessions,
            "context": self.context,
        }


class IOCExtractor:
    """Extracts indicators of compromise from honeypot events."""

    IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
    DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
    EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

    def __init__(self) -> None:
        self._seen_iocs: dict[tuple[str, str], ExtractedIOC] = {}

    PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]

    def is_public_ip(self, ip_str: str) -> bool:
        """Check if an IP address should be tracked as an external attacker IOC."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
                return False
            for net in self.PRIVATE_NETWORKS:
                if ip in net:
                    return False
            return True
        except ValueError:
            return False

    def extract_from_event(self, event: HoneypotEvent) -> list[ExtractedIOC]:
        """Extract all IOCs from a HoneypotEvent."""
        extracted: list[ExtractedIOC] = []
        now = event.timestamp or datetime.now(timezone.utc)
        session_id = event.session_id or ""
        event_type_str = event.event_type.value if isinstance(event.event_type, EventType) else str(event.event_type)

        # 1. Source IP (Direct Connection)
        if event.source_ip and self.is_public_ip(event.source_ip):
            extracted.append(
                ExtractedIOC(
                    type="ip_address",
                    value=event.source_ip,
                    confidence=1.0,
                    first_seen=now,
                    last_seen=now,
                    source_sessions=[session_id] if session_id else [],
                    context="source_connection",
                )
            )

        # 2. Authentication Credentials
        if event_type_str == EventType.AUTH_ATTEMPT.value or "username" in event.data:
            username = str(event.data.get("username", "")).strip()
            password = str(event.data.get("password", "")).strip()
            if username or password:
                cred_pair = f"{username}:{password}"
                extracted.append(
                    ExtractedIOC(
                        type="credential_pair",
                        value=cred_pair,
                        confidence=0.9,
                        first_seen=now,
                        last_seen=now,
                        source_sessions=[session_id] if session_id else [],
                        context="auth_attempt",
                    )
                )

        # 3. HTTP User-Agent and Host Headers
        if event.protocol == "http" or event_type_str == EventType.HTTP_REQUEST.value:
            ua = event.data.get("user_agent") or event.data.get("headers", {}).get("User-Agent")
            if ua and isinstance(ua, str) and len(ua.strip()) > 3:
                extracted.append(
                    ExtractedIOC(
                        type="user_agent",
                        value=ua.strip(),
                        confidence=0.85,
                        first_seen=now,
                        last_seen=now,
                        source_sessions=[session_id] if session_id else [],
                        context="http_header",
                    )
                )

            host = event.data.get("host") or event.data.get("headers", {}).get("Host")
            if host and isinstance(host, str):
                cleaned_host = host.split(":")[0].strip()
                if self.DOMAIN_PATTERN.match(cleaned_host) and not cleaned_host.endswith(".local") and cleaned_host != "localhost":
                    extracted.append(
                        ExtractedIOC(
                            type="domain",
                            value=cleaned_host,
                            confidence=0.8,
                            first_seen=now,
                            last_seen=now,
                            source_sessions=[session_id] if session_id else [],
                            context="http_host_header",
                        )
                    )

        # 4. Command Payloads (Wget / Curl / Scripts)
        cmd = str(event.data.get("command", "")).strip()
        if not cmd and event_type_str == EventType.FTP_COMMAND.value:
            cmd = str(event.data.get("raw_command", "")).strip()

        if cmd:
            # URLs
            for url in self.URL_PATTERN.findall(cmd):
                # Clean trailing punctuation often in commands
                cleaned_url = url.rstrip(");,\"'")
                extracted.append(
                    ExtractedIOC(
                        type="url",
                        value=cleaned_url,
                        confidence=0.9 if ("wget" in cmd.lower() or "curl" in cmd.lower()) else 0.7,
                        first_seen=now,
                        last_seen=now,
                        source_sessions=[session_id] if session_id else [],
                        context="command_invocation",
                    )
                )

            # Embedded IPs inside command
            for found_ip in self.IPV4_PATTERN.findall(cmd):
                if self.is_public_ip(found_ip) and found_ip != event.source_ip:
                    extracted.append(
                        ExtractedIOC(
                            type="ip_address",
                            value=found_ip,
                            confidence=0.75,
                            first_seen=now,
                            last_seen=now,
                            source_sessions=[session_id] if session_id else [],
                            context="command_ip_reference",
                        )
                    )

            # Emails
            for email in self.EMAIL_PATTERN.findall(cmd):
                extracted.append(
                    ExtractedIOC(
                        type="email",
                        value=email,
                        confidence=0.7,
                        first_seen=now,
                        last_seen=now,
                        source_sessions=[session_id] if session_id else [],
                        context="command_email_reference",
                    )
                )

        # Deduplicate results by (type, value) within this event
        deduped: dict[tuple[str, str], ExtractedIOC] = {}
        for ioc in extracted:
            key = (ioc.type, ioc.value)
            if key not in deduped:
                deduped[key] = ioc
            else:
                deduped[key].confidence = max(deduped[key].confidence, ioc.confidence)

        return list(deduped.values())
