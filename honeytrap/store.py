"""
HoneyTrap Storage Layer.

Asynchronous SQLite storage implementation using aiosqlite for events, sessions,
IOCs, MITRE ATT&CK statistics, and dashboard metrics.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncGenerator

import aiosqlite

from honeytrap.events import EventType, HoneypotEvent
from honeytrap.models import IOC, MITRETechnique, Session

logger = logging.getLogger(__name__)

# MITRE ATT&CK technique catalog for auto-populating names and tactics
MITRE_CATALOG: dict[str, tuple[str, str]] = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1110.002": ("Password Cracking", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1110.004": ("Credential Stuffing", "Credential Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1071.002": ("File Transfer Protocols", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1005": ("Data from Local System", "Collection"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance"),
}


def _iso_now() -> str:
    """Current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _format_datetime(dt: Any) -> str:
    """Format datetime or string into ISO 8601 string."""
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    if isinstance(dt, str):
        return dt
    return _iso_now()


class SQLiteStore:
    """Asynchronous SQLite storage provider for HoneyTrap."""

    def __init__(self, db_path: str = "data/honeytrap.db") -> None:
        """
        Initialize the SQLite store.

        :param db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._ensure_parent_dir()

    def _ensure_parent_dir(self) -> None:
        """Ensure parent directory for database exists."""
        db_file = Path(self.db_path)
        if db_file.parent and not db_file.parent.exists():
            db_file.parent.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def _get_connection(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """Context manager providing an aiosqlite connection with WAL mode and Row factory."""
        self._ensure_parent_dir()
        db = await aiosqlite.connect(self.db_path)
        try:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA busy_timeout=5000;")
            await db.execute("PRAGMA foreign_keys=ON;")
            yield db
        finally:
            await db.close()

    async def init_db(self) -> None:
        """Create tables and indexes if they do not already exist."""
        self._ensure_parent_dir()
        logger.info("Initializing HoneyTrap database at %s", self.db_path)
        async with self._get_connection() as db:
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    protocol TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    events_count INTEGER NOT NULL DEFAULT 0,
                    sensor_id TEXT NOT NULL DEFAULT 'honeytrap-01',
                    geo TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time DESC);
                CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol);
                CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);

                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    sensor_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    mitre_techniques TEXT NOT NULL,
                    geo TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
                CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol);
                CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
                CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);

                CREATE TABLE IF NOT EXISTS iocs (
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    source_sessions TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY (type, value)
                );

                CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
                CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen DESC);

                CREATE TABLE IF NOT EXISTS mitre_stats (
                    technique_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    tactic TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 1,
                    last_seen TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mitre_count ON mitre_stats(count DESC);
            """)
            await db.commit()
            logger.info("Database schema initialized successfully.")

    async def save_session(self, session: Session | dict[str, Any]) -> None:
        """
        Save or update a session record.

        :param session: Session instance or dictionary.
        """
        if isinstance(session, Session):
            data = session.to_dict()
        else:
            data = dict(session)

        session_id = str(data["id"])
        protocol = str(data["protocol"])
        source_ip = str(data["source_ip"])
        source_port = int(data["source_port"])
        start_time = _format_datetime(data.get("start_time"))
        end_time = _format_datetime(data["end_time"]) if data.get("end_time") else None
        events_count = int(data.get("events_count", 0))
        sensor_id = str(data.get("sensor_id", "honeytrap-01"))
        geo_json = json.dumps(data.get("geo")) if data.get("geo") is not None else None

        async with self._get_connection() as db:
            await db.execute(
                """
                INSERT INTO sessions (
                    id, protocol, source_ip, source_port, start_time,
                    end_time, events_count, sensor_id, geo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    end_time = COALESCE(excluded.end_time, sessions.end_time),
                    events_count = CASE
                        WHEN excluded.events_count > sessions.events_count THEN excluded.events_count
                        ELSE sessions.events_count
                    END,
                    geo = COALESCE(excluded.geo, sessions.geo)
                """,
                (
                    session_id,
                    protocol,
                    source_ip,
                    source_port,
                    start_time,
                    end_time,
                    events_count,
                    sensor_id,
                    geo_json,
                ),
            )
            await db.commit()

    async def save_event(self, event: HoneypotEvent | dict[str, Any]) -> None:
        """
        Save an event to the database, update session counters, and update MITRE ATT&CK & IOC statistics.

        :param event: HoneypotEvent instance or dictionary.
        """
        if isinstance(event, HoneypotEvent):
            data = event.to_dict()
        else:
            data = dict(event)

        event_id = str(data.get("id"))
        timestamp = _format_datetime(data.get("timestamp"))
        sensor_id = str(data.get("sensor_id", "honeytrap-01"))
        session_id = str(data.get("session_id", ""))
        protocol = str(data.get("protocol", ""))
        event_type = data.get("event_type")
        if isinstance(event_type, EventType):
            event_type = event_type.value
        else:
            event_type = str(event_type)
        source_ip = str(data.get("source_ip", ""))
        source_port = int(data.get("source_port", 0))

        payload = data.get("data", {})
        payload_json = json.dumps(payload)

        mitre_list = data.get("mitre_techniques", [])
        mitre_json = json.dumps(mitre_list)

        geo = data.get("geo")
        geo_json = json.dumps(geo) if geo is not None else None

        async with self._get_connection() as db:
            # 1. Ensure or update associated session record
            if session_id:
                await db.execute(
                    """
                    INSERT INTO sessions (
                        id, protocol, source_ip, source_port, start_time,
                        end_time, events_count, sensor_id, geo
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        end_time = excluded.end_time,
                        events_count = sessions.events_count + 1,
                        geo = COALESCE(sessions.geo, excluded.geo)
                    """,
                    (
                        session_id,
                        protocol,
                        source_ip,
                        source_port,
                        timestamp,
                        timestamp,
                        sensor_id,
                        geo_json,
                    ),
                )

            # 2. Insert event
            await db.execute(
                """
                INSERT OR REPLACE INTO events (
                    id, timestamp, sensor_id, session_id, protocol,
                    event_type, source_ip, source_port, data,
                    mitre_techniques, geo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    timestamp,
                    sensor_id,
                    session_id,
                    protocol,
                    event_type,
                    source_ip,
                    source_port,
                    payload_json,
                    mitre_json,
                    geo_json,
                ),
            )

            # 3. Update MITRE ATT&CK statistics
            if mitre_list:
                for item in mitre_list:
                    if isinstance(item, dict):
                        tech_id = str(item.get("technique_id", "")).strip()
                        name = str(item.get("name", "")).strip()
                        tactic = str(item.get("tactic", "")).strip()
                    else:
                        tech_id = str(item).strip()
                        default_info = MITRE_CATALOG.get(tech_id, (tech_id, "Unknown"))
                        name = default_info[0]
                        tactic = default_info[1]

                    if tech_id:
                        await db.execute(
                            """
                            INSERT INTO mitre_stats (technique_id, name, tactic, count, last_seen)
                            VALUES (?, ?, ?, 1, ?)
                            ON CONFLICT(technique_id) DO UPDATE SET
                                count = mitre_stats.count + 1,
                                last_seen = excluded.last_seen,
                                name = CASE WHEN mitre_stats.name != '' THEN mitre_stats.name ELSE excluded.name END,
                                tactic = CASE WHEN mitre_stats.tactic != '' THEN mitre_stats.tactic ELSE excluded.tactic END
                            """,
                            (tech_id, name, tactic, timestamp),
                        )

            # 4. Auto-register attacker IP as an IOC
            if source_ip and source_ip not in ("127.0.0.1", "::1", "localhost"):
                session_arr = [session_id] if session_id else []
                await self._save_ioc_internal(
                    db,
                    ioc_type="ip",
                    value=source_ip,
                    confidence=1.0,
                    timestamp=timestamp,
                    source_session=session_id,
                )

            await db.commit()

    async def _save_ioc_internal(
        self,
        db: aiosqlite.Connection,
        ioc_type: str,
        value: str,
        confidence: float,
        timestamp: str,
        source_session: str | None,
    ) -> None:
        """Internal helper to insert or update an IOC within an existing transaction."""
        async with db.execute(
            "SELECT source_sessions, confidence FROM iocs WHERE type = ? AND value = ?",
            (ioc_type, value),
        ) as cursor:
            row = await cursor.fetchone()

        if row is not None:
            try:
                sessions = json.loads(row["source_sessions"])
            except Exception:
                sessions = []
            if source_session and source_session not in sessions:
                sessions.append(source_session)
            new_conf = max(float(row["confidence"]), confidence)
            await db.execute(
                """
                UPDATE iocs
                SET confidence = ?, last_seen = ?, source_sessions = ?
                WHERE type = ? AND value = ?
                """,
                (new_conf, timestamp, json.dumps(sessions), ioc_type, value),
            )
        else:
            sessions = [source_session] if source_session else []
            await db.execute(
                """
                INSERT INTO iocs (type, value, confidence, first_seen, last_seen, source_sessions)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (ioc_type, value, confidence, timestamp, timestamp, json.dumps(sessions)),
            )

    async def save_ioc(self, ioc: IOC | dict[str, Any]) -> None:
        """
        Save or update an Indicator of Compromise.

        :param ioc: IOC instance or dictionary.
        """
        if isinstance(ioc, IOC):
            data = ioc.to_dict()
        else:
            data = dict(ioc)

        ioc_type = str(data["type"])
        value = str(data["value"])
        confidence = float(data.get("confidence", 1.0))
        first_seen = _format_datetime(data.get("first_seen"))
        last_seen = _format_datetime(data.get("last_seen"))
        source_sessions = list(data.get("source_sessions", []))

        async with self._get_connection() as db:
            async with db.execute(
                "SELECT source_sessions, confidence, first_seen FROM iocs WHERE type = ? AND value = ?",
                (ioc_type, value),
            ) as cursor:
                row = await cursor.fetchone()

            if row is not None:
                try:
                    existing_sessions = json.loads(row["source_sessions"])
                except Exception:
                    existing_sessions = []
                merged_sessions = list(dict.fromkeys(existing_sessions + source_sessions))
                new_conf = max(float(row["confidence"]), confidence)
                await db.execute(
                    """
                    UPDATE iocs
                    SET confidence = ?, last_seen = ?, source_sessions = ?
                    WHERE type = ? AND value = ?
                    """,
                    (new_conf, last_seen, json.dumps(merged_sessions), ioc_type, value),
                )
            else:
                await db.execute(
                    """
                    INSERT INTO iocs (type, value, confidence, first_seen, last_seen, source_sessions)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ioc_type,
                        value,
                        confidence,
                        first_seen,
                        last_seen,
                        json.dumps(source_sessions),
                    ),
                )
            await db.commit()

    async def get_events(
        self,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Retrieve paginated events with optional filtering.

        Supported filter keys:
        - protocol: str
        - event_type: str or EventType
        - source_ip: str
        - session_id: str
        - sensor_id: str
        - start_time / since / from_time: ISO string or datetime
        - end_time / until / to_time: ISO string or datetime
        - search: str (matches data payload or source_ip)

        :param filters: Dictionary of filter criteria.
        :param page: 1-indexed page number.
        :param per_page: Number of items per page.
        :return: List of event dictionaries.
        """
        filters = filters or {}
        clauses: list[str] = []
        params: list[Any] = []

        if filters.get("protocol"):
            clauses.append("protocol = ?")
            params.append(filters["protocol"])

        if filters.get("event_type"):
            val = filters["event_type"]
            if isinstance(val, EventType):
                val = val.value
            clauses.append("event_type = ?")
            params.append(str(val))

        if filters.get("source_ip"):
            clauses.append("source_ip = ?")
            params.append(filters["source_ip"])

        if filters.get("session_id"):
            clauses.append("session_id = ?")
            params.append(filters["session_id"])

        if filters.get("sensor_id"):
            clauses.append("sensor_id = ?")
            params.append(filters["sensor_id"])

        start_time = filters.get("start_time") or filters.get("since") or filters.get("from_time")
        if start_time:
            clauses.append("timestamp >= ?")
            params.append(_format_datetime(start_time))

        end_time = filters.get("end_time") or filters.get("until") or filters.get("to_time")
        if end_time:
            clauses.append("timestamp <= ?")
            params.append(_format_datetime(end_time))

        if filters.get("search"):
            clauses.append("(data LIKE ? OR source_ip LIKE ?)")
            search_param = f"%{filters['search']}%"
            params.extend([search_param, search_param])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        offset = max(0, (page - 1) * per_page)
        limit = max(1, per_page)
        params.extend([limit, offset])

        query = f"""
            SELECT id, timestamp, sensor_id, session_id, protocol, event_type,
                   source_ip, source_port, data, mitre_techniques, geo
            FROM events
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """

        async with self._get_connection() as db:
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()

        events: list[dict[str, Any]] = []
        for row in rows:
            events.append(self._row_to_event_dict(row))
        return events

    async def count_events(self, filters: dict[str, Any] | None = None) -> int:
        """Count total events matching filter criteria."""
        filters = filters or {}
        clauses: list[str] = []
        params: list[Any] = []

        if filters.get("protocol"):
            clauses.append("protocol = ?")
            params.append(filters["protocol"])

        if filters.get("event_type"):
            val = filters["event_type"]
            if isinstance(val, EventType):
                val = val.value
            clauses.append("event_type = ?")
            params.append(str(val))

        if filters.get("source_ip"):
            clauses.append("source_ip = ?")
            params.append(filters["source_ip"])

        if filters.get("session_id"):
            clauses.append("session_id = ?")
            params.append(filters["session_id"])

        start_time = filters.get("start_time") or filters.get("since") or filters.get("from_time")
        if start_time:
            clauses.append("timestamp >= ?")
            params.append(_format_datetime(start_time))

        end_time = filters.get("end_time") or filters.get("until") or filters.get("to_time")
        if end_time:
            clauses.append("timestamp <= ?")
            params.append(_format_datetime(end_time))

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT COUNT(*) as total FROM events {where_sql}"

        async with self._get_connection() as db:
            async with db.execute(query, params) as cursor:
                row = await cursor.fetchone()
                return int(row["total"]) if row else 0

    def _row_to_event_dict(self, row: aiosqlite.Row) -> dict[str, Any]:
        """Convert SQLite events row to dictionary with parsed JSON fields."""
        try:
            data = json.loads(row["data"]) if row["data"] else {}
        except Exception:
            data = {"raw": row["data"]}

        try:
            mitre = json.loads(row["mitre_techniques"]) if row["mitre_techniques"] else []
        except Exception:
            mitre = []

        try:
            geo = json.loads(row["geo"]) if row["geo"] else None
        except Exception:
            geo = None

        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "sensor_id": row["sensor_id"],
            "session_id": row["session_id"],
            "protocol": row["protocol"],
            "event_type": row["event_type"],
            "source_ip": row["source_ip"],
            "source_port": row["source_port"],
            "data": data,
            "mitre_techniques": mitre,
            "geo": geo,
        }

    async def get_sessions(
        self,
        page: int = 1,
        per_page: int = 50,
        protocol: str | None = None,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve paginated sessions ordered by start time descending.

        :param page: 1-indexed page number.
        :param per_page: Items per page.
        :param protocol: Optional protocol filter.
        :param source_ip: Optional source IP filter.
        :return: List of session dictionaries.
        """
        clauses: list[str] = []
        params: list[Any] = []

        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol)

        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        offset = max(0, (page - 1) * per_page)
        limit = max(1, per_page)
        params.extend([limit, offset])

        query = f"""
            SELECT id, protocol, source_ip, source_port, start_time,
                   end_time, events_count, sensor_id, geo
            FROM sessions
            {where_sql}
            ORDER BY start_time DESC
            LIMIT ? OFFSET ?
        """

        async with self._get_connection() as db:
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            try:
                geo = json.loads(row["geo"]) if row["geo"] else None
            except Exception:
                geo = None

            results.append({
                "id": row["id"],
                "protocol": row["protocol"],
                "source_ip": row["source_ip"],
                "source_port": row["source_port"],
                "start_time": row["start_time"],
                "end_time": row["end_time"],
                "events_count": row["events_count"],
                "sensor_id": row["sensor_id"],
                "geo": geo,
            })
        return results

    async def count_sessions(
        self,
        protocol: str | None = None,
        source_ip: str | None = None,
    ) -> int:
        """Count total sessions matching filter criteria."""
        clauses: list[str] = []
        params: list[Any] = []

        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol)

        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT COUNT(*) as total FROM sessions {where_sql}"

        async with self._get_connection() as db:
            async with db.execute(query, params) as cursor:
                row = await cursor.fetchone()
                return int(row["total"]) if row else 0

    async def get_session_detail(self, session_id: str) -> dict[str, Any] | None:
        """
        Retrieve detailed session record including all associated events in chronological order.

        :param session_id: Session identifier string.
        :return: Session dict containing 'events' list, or None if session not found.
        """
        async with self._get_connection() as db:
            async with db.execute(
                """
                SELECT id, protocol, source_ip, source_port, start_time,
                       end_time, events_count, sensor_id, geo
                FROM sessions
                WHERE id = ?
                """,
                (session_id,),
            ) as cursor:
                sess_row = await cursor.fetchone()

            if sess_row is None:
                return None

            try:
                geo = json.loads(sess_row["geo"]) if sess_row["geo"] else None
            except Exception:
                geo = None

            session_dict: dict[str, Any] = {
                "id": sess_row["id"],
                "protocol": sess_row["protocol"],
                "source_ip": sess_row["source_ip"],
                "source_port": sess_row["source_port"],
                "start_time": sess_row["start_time"],
                "end_time": sess_row["end_time"],
                "events_count": sess_row["events_count"],
                "sensor_id": sess_row["sensor_id"],
                "geo": geo,
            }

            async with db.execute(
                """
                SELECT id, timestamp, sensor_id, session_id, protocol, event_type,
                       source_ip, source_port, data, mitre_techniques, geo
                FROM events
                WHERE session_id = ?
                ORDER BY timestamp ASC
                """,
                (session_id,),
            ) as cursor:
                event_rows = await cursor.fetchall()

            session_dict["events"] = [self._row_to_event_dict(r) for r in event_rows]
            return session_dict

    async def get_stats(self) -> dict[str, Any]:
        """
        Retrieve dashboard overview statistics.

        Includes total sessions, total events, unique attacker IPs, protocol breakdown,
        event type breakdown, 24-hour activity trends, top techniques, and top attackers.
        """
        async with self._get_connection() as db:
            # Total sessions
            async with db.execute("SELECT COUNT(*) as total FROM sessions") as cursor:
                row = await cursor.fetchone()
                total_sessions = int(row["total"]) if row else 0

            # Total events
            async with db.execute("SELECT COUNT(*) as total FROM events") as cursor:
                row = await cursor.fetchone()
                total_events = int(row["total"]) if row else 0

            # Unique attacker IPs
            async with db.execute("SELECT COUNT(DISTINCT source_ip) as total FROM events") as cursor:
                row = await cursor.fetchone()
                unique_ips = int(row["total"]) if row else 0

            # Protocol breakdown
            async with db.execute("SELECT protocol, COUNT(*) as cnt FROM events GROUP BY protocol") as cursor:
                rows = await cursor.fetchall()
                protocol_breakdown = {r["protocol"]: r["cnt"] for r in rows}

            # Event type breakdown
            async with db.execute("SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type") as cursor:
                rows = await cursor.fetchall()
                event_type_breakdown = {r["event_type"]: r["cnt"] for r in rows}

            # 24-hour statistics
            yesterday_iso = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            async with db.execute(
                "SELECT COUNT(*) as cnt FROM events WHERE timestamp >= ?",
                (yesterday_iso,),
            ) as cursor:
                row = await cursor.fetchone()
                events_last_24h = int(row["cnt"]) if row else 0

            async with db.execute(
                "SELECT COUNT(*) as cnt FROM sessions WHERE start_time >= ?",
                (yesterday_iso,),
            ) as cursor:
                row = await cursor.fetchone()
                sessions_last_24h = int(row["cnt"]) if row else 0

            # Total IOCs
            async with db.execute("SELECT COUNT(*) as total FROM iocs") as cursor:
                row = await cursor.fetchone()
                total_iocs = int(row["total"]) if row else 0

        # Top MITRE techniques and top attackers
        top_techniques = await self.get_mitre_stats()
        top_attackers = await self.get_top_attackers(limit=5)

        return {
            "total_sessions": total_sessions,
            "total_events": total_events,
            "unique_ips": unique_ips,
            "protocol_breakdown": protocol_breakdown,
            "event_type_breakdown": event_type_breakdown,
            "events_last_24h": events_last_24h,
            "sessions_last_24h": sessions_last_24h,
            "total_iocs": total_iocs,
            "top_techniques": top_techniques[:5],
            "top_attackers": top_attackers,
        }

    async def get_iocs(self, ioc_type: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """
        Retrieve list of Indicators of Compromise.

        :param ioc_type: Optional IOC type filter ('ip', 'hash', 'url', etc.).
        :param limit: Maximum records to return.
        :return: List of IOC dictionaries.
        """
        params: list[Any] = []
        where_clause = ""
        if ioc_type:
            where_clause = "WHERE type = ?"
            params.append(ioc_type)

        params.append(max(1, limit))
        query = f"""
            SELECT type, value, confidence, first_seen, last_seen, source_sessions
            FROM iocs
            {where_clause}
            ORDER BY last_seen DESC
            LIMIT ?
        """

        async with self._get_connection() as db:
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            try:
                sessions = json.loads(row["source_sessions"]) if row["source_sessions"] else []
            except Exception:
                sessions = []

            results.append({
                "type": row["type"],
                "value": row["value"],
                "confidence": row["confidence"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "source_sessions": sessions,
            })
        return results

    async def get_mitre_stats(self) -> list[dict[str, Any]]:
        """
        Retrieve MITRE ATT&CK technique statistics ordered by occurrence count.

        :return: List of technique dictionaries (technique_id, name, tactic, count, last_seen).
        """
        async with self._get_connection() as db:
            async with db.execute(
                """
                SELECT technique_id, name, tactic, count, last_seen
                FROM mitre_stats
                ORDER BY count DESC
                """
            ) as cursor:
                rows = await cursor.fetchall()

        return [
            {
                "technique_id": r["technique_id"],
                "name": r["name"],
                "tactic": r["tactic"],
                "count": r["count"],
                "last_seen": r["last_seen"],
            }
            for r in rows
        ]

    async def get_top_attackers(self, limit: int = 10) -> list[dict[str, Any]]:
        """
        Retrieve top attacker IP addresses by total event volume.

        :param limit: Maximum number of attackers to return.
        :return: List of attacker summaries including event count, session count, protocols, and geo.
        """
        async with self._get_connection() as db:
            async with db.execute(
                """
                SELECT
                    source_ip,
                    COUNT(id) as event_count,
                    COUNT(DISTINCT session_id) as session_count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    GROUP_CONCAT(DISTINCT protocol) as protocols_str
                FROM events
                WHERE source_ip != ''
                GROUP BY source_ip
                ORDER BY event_count DESC
                LIMIT ?
                """,
                (max(1, limit),),
            ) as cursor:
                rows = await cursor.fetchall()

            attackers: list[dict[str, Any]] = []
            for row in rows:
                ip = row["source_ip"]
                # Fetch geo for this IP if available
                async with db.execute(
                    "SELECT geo FROM events WHERE source_ip = ? AND geo IS NOT NULL LIMIT 1",
                    (ip,),
                ) as geo_cursor:
                    geo_row = await geo_cursor.fetchone()

                geo_dict = None
                if geo_row and geo_row["geo"]:
                    try:
                        geo_dict = json.loads(geo_row["geo"])
                    except Exception:
                        pass

                protocols = (row["protocols_str"] or "").split(",")
                protocols = [p.strip() for p in protocols if p.strip()]

                attackers.append({
                    "source_ip": ip,
                    "event_count": row["event_count"],
                    "session_count": row["session_count"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "protocols": protocols,
                    "geo": geo_dict,
                })

        return attackers


# Global default store instance and functional facade
_default_store: SQLiteStore | None = None


def get_store(db_path: str = "data/honeytrap.db") -> SQLiteStore:
    """Get or create the default SQLiteStore instance."""
    global _default_store
    if _default_store is None or _default_store.db_path != db_path:
        _default_store = SQLiteStore(db_path)
    return _default_store


async def init_db(db_path: str = "data/honeytrap.db") -> None:
    """Initialize database schema on the default store."""
    await get_store(db_path).init_db()


async def save_event(event: HoneypotEvent | dict[str, Any], db_path: str = "data/honeytrap.db") -> None:
    """Save event via default store."""
    await get_store(db_path).save_event(event)


async def save_session(session: Session | dict[str, Any], db_path: str = "data/honeytrap.db") -> None:
    """Save session via default store."""
    await get_store(db_path).save_session(session)


async def get_events(
    filters: dict[str, Any] | None = None,
    page: int = 1,
    per_page: int = 50,
    db_path: str = "data/honeytrap.db",
) -> list[dict[str, Any]]:
    """Retrieve events via default store."""
    return await get_store(db_path).get_events(filters, page, per_page)


async def get_sessions(
    page: int = 1,
    per_page: int = 50,
    protocol: str | None = None,
    source_ip: str | None = None,
    db_path: str = "data/honeytrap.db",
) -> list[dict[str, Any]]:
    """Retrieve sessions via default store."""
    return await get_store(db_path).get_sessions(page, per_page, protocol, source_ip)


async def get_session_detail(session_id: str, db_path: str = "data/honeytrap.db") -> dict[str, Any] | None:
    """Retrieve session detail via default store."""
    return await get_store(db_path).get_session_detail(session_id)


async def get_stats(db_path: str = "data/honeytrap.db") -> dict[str, Any]:
    """Retrieve overview stats via default store."""
    return await get_store(db_path).get_stats()


async def save_ioc(ioc: IOC | dict[str, Any], db_path: str = "data/honeytrap.db") -> None:
    """Save IOC via default store."""
    await get_store(db_path).save_ioc(ioc)


async def get_iocs(ioc_type: str | None = None, limit: int = 100, db_path: str = "data/honeytrap.db") -> list[dict[str, Any]]:
    """Retrieve IOCs via default store."""
    return await get_store(db_path).get_iocs(ioc_type, limit)


async def get_mitre_stats(db_path: str = "data/honeytrap.db") -> list[dict[str, Any]]:
    """Retrieve MITRE ATT&CK statistics via default store."""
    return await get_store(db_path).get_mitre_stats()


async def get_top_attackers(limit: int = 10, db_path: str = "data/honeytrap.db") -> list[dict[str, Any]]:
    """Retrieve top attackers via default store."""
    return await get_store(db_path).get_top_attackers(limit)


Store = SQLiteStore

__all__ = [
    "Store",
    "SQLiteStore",
    "get_store",
    "init_db",
    "save_event",
    "save_session",
    "get_events",
    "get_sessions",
    "get_session_detail",
    "get_stats",
    "save_ioc",
    "get_iocs",
    "get_mitre_stats",
    "get_top_attackers",
]
