"""Blocklist Exporter for HoneyTrap.

Exports attacker IP addresses into multiple actionable firewall and server formats:
- iptables rules
- nginx deny directives
- plain text (one IP per line)
- CSV with geo metadata
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AttackerInfo:
    """Attacker summary information for blocklist generation."""
    ip: str
    country: str = "Unknown"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    attack_count: int = 1
    protocols: list[str] = field(default_factory=list)


class BlocklistExporter:
    """Formats attacker IPs into firewall/reverse-proxy rules."""

    @staticmethod
    def _normalize_attackers(attackers: list[AttackerInfo | dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for a in attackers:
            if isinstance(a, AttackerInfo):
                geo_country = a.country
                protocols = a.protocols
                normalized.append({
                    "ip": a.ip,
                    "country": geo_country,
                    "first_seen": a.first_seen.isoformat() if isinstance(a.first_seen, datetime) else str(a.first_seen),
                    "last_seen": a.last_seen.isoformat() if isinstance(a.last_seen, datetime) else str(a.last_seen),
                    "attack_count": a.attack_count,
                    "protocols": protocols,
                })
            elif isinstance(a, dict):
                ip = a.get("source_ip") or a.get("ip") or ""
                geo = a.get("geo") or {}
                country = geo.get("country") if isinstance(geo, dict) else a.get("country", "Unknown")
                normalized.append({
                    "ip": str(ip).strip(),
                    "country": str(country or "Unknown"),
                    "first_seen": str(a.get("first_seen", "")),
                    "last_seen": str(a.get("last_seen", "")),
                    "attack_count": int(a.get("event_count") or a.get("attack_count") or 1),
                    "protocols": a.get("protocols", []),
                })
        return [item for item in normalized if item["ip"]]

    def export_iptables(self, attackers: list[AttackerInfo | dict[str, Any]]) -> str:
        """Generate iptables drop rules."""
        items = self._normalize_attackers(attackers)
        lines = [
            "# HoneyTrap Automated Firewall Blocklist - iptables",
            "# Generated automatically from active honeypot attacks",
            "",
        ]
        for item in items:
            lines.append(f"iptables -A INPUT -s {item['ip']} -j DROP")
        return "\n".join(lines) + "\n"

    def export_nginx(self, attackers: list[AttackerInfo | dict[str, Any]]) -> str:
        """Generate nginx deny statements."""
        items = self._normalize_attackers(attackers)
        lines = [
            "# HoneyTrap Automated Deny Blocklist - nginx",
            "# Include in http or server block: include /etc/nginx/blocklist.conf;",
            "",
        ]
        for item in items:
            lines.append(f"deny {item['ip']};")
        return "\n".join(lines) + "\n"

    def export_plaintext(self, attackers: list[AttackerInfo | dict[str, Any]]) -> str:
        """Generate one IP per line text."""
        items = self._normalize_attackers(attackers)
        return "\n".join(item["ip"] for item in items) + ("\n" if items else "")

    def export_csv(self, attackers: list[AttackerInfo | dict[str, Any]]) -> str:
        """Generate CSV with IP, country, first seen, last seen, count, and protocols."""
        items = self._normalize_attackers(attackers)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ip", "country", "first_seen", "last_seen", "attack_count", "protocols"])
        for item in items:
            protocols_str = "|".join(item["protocols"]) if isinstance(item["protocols"], list) else str(item["protocols"])
            writer.writerow([
                item["ip"],
                item["country"],
                item["first_seen"],
                item["last_seen"],
                item["attack_count"],
                protocols_str,
            ])
        return output.getvalue()
