"""MITRE ATT&CK Mapping Engine for HoneyTrap.

Maps honeypot events to MITRE ATT&CK techniques based on single-event rules
and sliding-window behavioral detection (e.g. brute force, password spraying).
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from honeytrap.events import EventType, HoneypotEvent

logger = logging.getLogger(__name__)


@dataclass
class TechniqueDefinition:
    """Represents a MITRE ATT&CK technique definition."""
    technique_id: str
    name: str
    tactic: str
    description: str


# 15 MITRE ATT&CK techniques supported by HoneyTrap
TECHNIQUE_CATALOG: dict[str, TechniqueDefinition] = {
    "T1078": TechniqueDefinition(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Initial Access",
        description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
    ),
    "T1190": TechniqueDefinition(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Adversaries may attempt to exploit vulnerabilities in Internet-facing applications to gain access.",
    ),
    "T1110": TechniqueDefinition(
        technique_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description="Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
    ),
    "T1110.001": TechniqueDefinition(
        technique_id="T1110.001",
        name="Password Guessing",
        tactic="Credential Access",
        description="Adversaries may guess passwords to attempt access to accounts using common dictionary words.",
    ),
    "T1110.003": TechniqueDefinition(
        technique_id="T1110.003",
        name="Password Spraying",
        tactic="Credential Access",
        description="Adversaries may use a single password against many different accounts to avoid lockouts.",
    ),
    "T1059": TechniqueDefinition(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversaries may abuse command and script interpreters to execute arbitrary commands.",
    ),
    "T1059.004": TechniqueDefinition(
        technique_id="T1059.004",
        name="Unix Shell",
        tactic="Execution",
        description="Adversaries may abuse Unix shells to execute various commands or scripts.",
    ),
    "T1083": TechniqueDefinition(
        technique_id="T1083",
        name="File and Directory Discovery",
        tactic="Discovery",
        description="Adversaries may enumerate files and directories or search in specific locations.",
    ),
    "T1082": TechniqueDefinition(
        technique_id="T1082",
        name="System Information Discovery",
        tactic="Discovery",
        description="Adversaries may attempt to get detailed information about the operating system and hardware.",
    ),
    "T1016": TechniqueDefinition(
        technique_id="T1016",
        name="System Network Configuration Discovery",
        tactic="Discovery",
        description="Adversaries may look for details about the network configuration and settings.",
    ),
    "T1005": TechniqueDefinition(
        technique_id="T1005",
        name="Data from Local System",
        tactic="Collection",
        description="Adversaries may search local system sources, such as file systems, to find files of interest.",
    ),
    "T1021": TechniqueDefinition(
        technique_id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        description="Adversaries may use valid accounts to log into a service that accepts remote connections.",
    ),
    "T1021.004": TechniqueDefinition(
        technique_id="T1021.004",
        name="SSH",
        tactic="Lateral Movement",
        description="Adversaries may communicate using SSH to remotely access systems.",
    ),
    "T1071.001": TechniqueDefinition(
        technique_id="T1071.001",
        name="Web Protocols",
        tactic="Command and Control",
        description="Adversaries may communicate using application layer protocols (HTTP/HTTPS) to avoid detection.",
    ),
    "T1105": TechniqueDefinition(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        description="Adversaries may transfer tools or other files from an external system into a compromised environment.",
    ),
}

# Common passwords list for password guessing detection
COMMON_PASSWORDS: list[str] = [
    "admin",
    "admin123",
    "password",
    "123456",
    "12345678",
    "123456789",
    "12345",
    "1234",
    "111111",
    "root",
    "toor",
    "guest",
    "qwerty",
    "default",
    "pass",
    "test",
    "user",
    "master",
    "access",
    "secret",
    "login",
    "welcome",
    "changeme",
    "letmein",
    "raspberry",
    "ubuntu",
    "service",
    "oracle",
    "support",
    "super",
]


class MITREMapper:
    """
    Maps HoneypotEvent occurrences to MITRE ATT&CK techniques.

    Uses a blend of single-event signature rules and sliding window behavioral
    state (such as brute force tracking per IP and credential spraying per password).
    """

    def __init__(self, brute_force_window_sec: float = 60.0, brute_force_threshold: int = 5) -> None:
        """
        Initialize the MITRE mapping engine.

        :param brute_force_window_sec: Sliding window duration in seconds for brute force detection.
        :param brute_force_threshold: Minimum failed auth attempts in the window to trigger T1110.
        """
        self.brute_force_window_sec = brute_force_window_sec
        self.brute_force_threshold = brute_force_threshold

        # IP -> list of failed attempt timestamps (UTC datetime or timestamp float)
        self._auth_failures: dict[str, list[float]] = defaultdict(list)

        # Password -> list of (username, timestamp float)
        self._password_spray_history: dict[str, list[tuple[str, float]]] = defaultdict(list)

        # Running statistics: technique_id -> count of matches
        self._stats: dict[str, int] = defaultdict(int)

        self._common_passwords_set = {p.strip().lower() for p in COMMON_PASSWORDS}

    def analyze_event(self, event: HoneypotEvent) -> list[str]:
        """
        Analyze an event and return a list of matching MITRE ATT&CK technique IDs.

        :param event: HoneypotEvent to analyze
        :return: List of technique IDs (e.g. ['T1078', 'T1021.004'])
        """
        matched: list[str] = []
        event_time = event.timestamp.timestamp() if event.timestamp else datetime.now(timezone.utc).timestamp()
        protocol = (event.protocol or "").lower()
        event_type_str = event.event_type.value if isinstance(event.event_type, EventType) else str(event.event_type)

        # 1. Authentication Attempts & Remote Services
        if event_type_str == EventType.AUTH_ATTEMPT.value or "username" in event.data:
            success = bool(event.data.get("success", False))
            username = str(event.data.get("username", ""))
            password = str(event.data.get("password", ""))

            if success:
                # T1078 - Valid Accounts
                matched.append("T1078")
                # T1021 / T1021.004 - Remote Services / SSH
                if protocol == "ssh":
                    matched.append("T1021.004")
                    matched.append("T1021")
                elif protocol == "ftp":
                    matched.append("T1021")
            else:
                # Track auth failure for sliding window brute force
                ip = event.source_ip or "unknown"
                self._auth_failures[ip].append(event_time)
                # Purge old failures outside the window
                cutoff = event_time - self.brute_force_window_sec
                self._auth_failures[ip] = [t for t in self._auth_failures[ip] if t >= cutoff]

                # 5+ failures in 60s from same IP -> T1110 (Brute Force)
                if len(self._auth_failures[ip]) >= self.brute_force_threshold:
                    matched.append("T1110")

            # Password Guessing (T1110.001) - auth attempts with common passwords
            if password and password.lower() in self._common_passwords_set:
                matched.append("T1110.001")

            # Password Spraying (T1110.003) - same password across 3+ different usernames
            if password and username:
                spray_cutoff = event_time - 300.0  # 5-minute sliding window
                history = self._password_spray_history[password]
                history.append((username, event_time))
                self._password_spray_history[password] = [(u, t) for u, t in history if t >= spray_cutoff]

                distinct_users = {u for u, _ in self._password_spray_history[password]}
                if len(distinct_users) >= 3:
                    matched.append("T1110.003")

        # Remote Services connection without auth (or session start)
        if event_type_str in (EventType.CONNECTION.value, EventType.SESSION_START.value):
            if protocol == "ssh":
                matched.append("T1021.004")
                matched.append("T1021")
            elif protocol == "ftp":
                matched.append("T1021")

        # 2. HTTP Exploit Attempts (T1190)
        if event_type_str == EventType.HTTP_REQUEST.value or protocol == "http":
            matched.append("T1190")

        # 3. Shell Commands / FTP Commands
        cmd = str(event.data.get("command", "")).strip()
        if not cmd and event_type_str == EventType.FTP_COMMAND.value:
            cmd = str(event.data.get("raw_command", "")).strip()

        if cmd or event_type_str == EventType.COMMAND.value:
            cmd_lower = cmd.lower()

            # T1059 - Command and Scripting Interpreter (any shell command)
            matched.append("T1059")

            # T1059.004 - Unix Shell (commands invoking or executing via bash, sh, etc.)
            if any(term in cmd_lower for term in ("bash", "sh ", "sh\t", "/bin/sh", "/bin/bash", "zsh", "dash", "exec ")):
                matched.append("T1059.004")

            # T1083 - File and Directory Discovery: ls, find, dir commands
            if re.search(r"\b(ls|dir|find|tree|locate|pwd)\b", cmd_lower):
                matched.append("T1083")

            # T1082 - System Information Discovery: uname, hostname, whoami, id
            if re.search(r"\b(uname|hostname|whoami|id|arch|systeminfo|uptime)\b", cmd_lower):
                matched.append("T1082")

            # T1016 - System Network Configuration Discovery: ifconfig, ip addr, netstat
            if (
                re.search(r"\b(ifconfig|netstat|route|arp)\b", cmd_lower)
                or "ip addr" in cmd_lower
                or "ip a" in cmd_lower
                or "ip route" in cmd_lower
                or "ip link" in cmd_lower
            ):
                matched.append("T1016")

            # T1005 - Data from Local System: cat sensitive files
            if (
                re.search(r"\b(cat|head|tail|more|less)\b", cmd_lower)
                or "/etc/passwd" in cmd_lower
                or "/etc/shadow" in cmd_lower
                or "/etc/hosts" in cmd_lower
                or ".ssh" in cmd_lower
            ):
                matched.append("T1005")

            # T1071.001 - Web Protocols (C2): wget/curl to external URLs
            if ("wget" in cmd_lower or "curl" in cmd_lower) and ("http://" in cmd_lower or "https://" in cmd_lower):
                matched.append("T1071.001")
            elif "http://" in cmd_lower or "https://" in cmd_lower:
                matched.append("T1071.001")

            # T1105 - Ingress Tool Transfer (C2): wget/curl downloading files
            if any(tool in cmd_lower for tool in ("wget", "curl", "tftp", "ftp ", "scp ", "sftp ")):
                matched.append("T1105")

        # 4. File uploads
        if event_type_str == EventType.FILE_UPLOAD.value:
            matched.append("T1105")

        # Deduplicate while preserving order
        unique_matched = list(dict.fromkeys(matched))

        # Update stats
        for tid in unique_matched:
            self._stats[tid] += 1

        return unique_matched

    def get_technique_info(self, technique_id: str) -> TechniqueDefinition | None:
        """
        Get technique definition by ID.

        :param technique_id: MITRE technique ID (e.g. 'T1110')
        :return: TechniqueDefinition or None if not found
        """
        return TECHNIQUE_CATALOG.get(technique_id)

    def get_all_techniques(self) -> list[TechniqueDefinition]:
        """
        Return all technique definitions in the catalog.

        :return: List of all 15 TechniqueDefinition objects
        """
        return list(TECHNIQUE_CATALOG.values())

    def get_stats(self) -> dict[str, int]:
        """
        Return mapping of technique ID to observation count.

        :return: Dict of {technique_id: count}
        """
        return dict(self._stats)
