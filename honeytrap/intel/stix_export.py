"""STIX 2.1 Threat Intelligence Bundle Generator for HoneyTrap."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class STIXExporter:
    """Generates STIX 2.1 compliant bundles from HoneyTrap observations."""

    def __init__(self, sensor_id: str = "honeytrap-01") -> None:
        self.sensor_id = sensor_id

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _format_time(self, val: Any) -> str:
        if isinstance(val, datetime):
            if val.tzinfo is None:
                val = val.replace(tzinfo=timezone.utc)
            return val.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                pass
        return self._now_iso()

    def export_bundle(
        self,
        events: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
        techniques: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Build and return a STIX 2.1 bundle dictionary containing:
        - Identity (HoneyTrap Honeypot Sensor)
        - Indicators for extracted IOCs
        - AttackPattern objects for observed MITRE ATT&CK techniques
        - Relationships connecting Indicators to AttackPatterns
        """
        now = self._now_iso()
        objects: list[dict[str, Any]] = []

        # 1. Identity
        identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, f'honeytrap.{self.sensor_id}')}"
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": f"HoneyTrap Sensor ({self.sensor_id})",
            "description": "Automated honeypot detection sensor",
            "identity_class": "system",
        }
        objects.append(identity)

        # 2. Attack Patterns (MITRE techniques)
        technique_id_map: dict[str, str] = {}
        for tech in techniques:
            tech_id = tech.get("technique_id", "")
            name = tech.get("name", tech_id)
            tactic = tech.get("tactic", "Unknown")

            stix_ap_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, f'mitre.{tech_id}')}"
            technique_id_map[tech_id] = stix_ap_id

            attack_pattern = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": stix_ap_id,
                "created": now,
                "modified": now,
                "name": f"{name} ({tech_id})",
                "description": f"MITRE ATT&CK Technique {tech_id} under tactic {tactic}",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": tactic.lower().replace(" ", "-"),
                    }
                ],
                "created_by_ref": identity_id,
            }
            objects.append(attack_pattern)

        # 3. Indicators from IOCs
        indicator_ids: list[str] = []
        for ioc in iocs:
            ioc_type = ioc.get("type", "")
            val = str(ioc.get("value", "")).strip()
            if not val:
                continue

            # Determine STIX 2.1 pattern
            pattern = None
            indicator_types = ["malicious-activity"]

            if ioc_type in ("ip", "ip_address"):
                pattern = f"[ipv4-addr:value = '{val}']"
            elif ioc_type == "url":
                pattern = f"[url:value = '{val}']"
            elif ioc_type == "domain":
                pattern = f"[domain-name:value = '{val}']"
            elif ioc_type == "credential_pair":
                pattern = f"[user-account:user_id = '{val.split(':')[0]}']"
                indicator_types = ["compromised-credential"]
            elif ioc_type == "user_agent":
                pattern = f"[network-traffic:src_payload_ref.value = '{val}']"

            if not pattern:
                pattern = f"[file:name = '{val}']"

            first_seen = self._format_time(ioc.get("first_seen"))
            stix_ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'{ioc_type}.{val}')}"
            indicator_ids.append(stix_ind_id)

            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": stix_ind_id,
                "created": first_seen,
                "modified": now,
                "name": f"Honeypot {ioc_type.upper()}: {val}",
                "description": f"Extracted by HoneyTrap sensor from observed attack sessions",
                "indicator_types": indicator_types,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": first_seen,
                "confidence": int(float(ioc.get("confidence", 1.0)) * 100),
                "created_by_ref": identity_id,
            }
            objects.append(indicator)

        # 4. Relationships linking Indicators to primary Attack Patterns
        if technique_id_map and indicator_ids:
            first_ap_id = next(iter(technique_id_map.values()))
            for ind_id in indicator_ids[:20]:  # Link top indicators
                rel_id = f"relationship--{uuid.uuid5(uuid.NAMESPACE_DNS, f'{ind_id}->{first_ap_id}')}"
                rel = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": first_ap_id,
                    "created_by_ref": identity_id,
                }
                objects.append(rel)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }
        return bundle
