"""
HoneyTrap Configuration Module.

Loads configuration from YAML file with environment variable overrides.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class SSHConfig:
    enabled: bool = True
    port: int = 2222
    host_key_file: str = "data/ssh_host_key"
    banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
    max_auth_attempts: int = 6


@dataclass
class HTTPConfig:
    enabled: bool = True
    port: int = 8080
    server_header: str = "Apache/2.4.54 (Ubuntu)"


@dataclass
class FTPConfig:
    enabled: bool = True
    port: int = 2121
    banner: str = "220 (vsFTPd 3.0.5)"
    pasv_port_range: tuple[int, int] = (30000, 30100)


@dataclass
class APIConfig:
    host: str = "0.0.0.0"
    port: int = 3000
    cors_origins: list[str] = field(default_factory=lambda: ["*"])


@dataclass
class GeoConfig:
    enabled: bool = True
    cache_ttl: int = 86400


@dataclass
class Config:
    sensor_id: str = "honeytrap-01"
    data_dir: str = "data"
    db_path: str = "data/honeytrap.db"
    ssh: SSHConfig = field(default_factory=SSHConfig)
    http: HTTPConfig = field(default_factory=HTTPConfig)
    ftp: FTPConfig = field(default_factory=FTPConfig)
    api: APIConfig = field(default_factory=APIConfig)
    geo: GeoConfig = field(default_factory=GeoConfig)


def _str_to_bool(value: Any) -> bool:
    """Convert string/value to boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("true", "1", "yes", "on", "t")


def _parse_port_range(value: Any) -> tuple[int, int]:
    """Parse port range from list, tuple, or string like '30000-30100' or '30000,30100'."""
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return (int(value[0]), int(value[1]))
    if isinstance(value, str):
        cleaned = value.replace(" ", "").replace("-", ",")
        parts = cleaned.split(",")
        if len(parts) == 2:
            return (int(parts[0]), int(parts[1]))
    return (30000, 30100)


def _parse_cors_origins(value: Any) -> list[str]:
    """Parse CORS origins from list, JSON array string, or comma-separated string."""
    if isinstance(value, list):
        return [str(item).strip() for item in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed]
            except json.JSONDecodeError:
                pass
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return ["*"]


def load_config(path: str = "config.yaml") -> Config:
    """
    Load configuration from YAML file and merge with environment variables.

    Environment variables use the HONEYTRAP_ prefix and take precedence over YAML values.
    Example: HONEYTRAP_SSH_PORT=2222, HONEYTRAP_API_HOST=127.0.0.1
    """
    raw_data: dict[str, Any] = {}
    config_file = Path(path)

    if config_file.is_file():
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    raw_data = loaded
        except Exception as exc:
            logger.warning("Failed to load config file %s: %s; using defaults", path, exc)
    else:
        logger.debug("Config file not found at %s; checking environment variables and defaults", path)

    # Base config
    sensor_id = os.getenv("HONEYTRAP_SENSOR_ID", raw_data.get("sensor_id", "honeytrap-01"))
    data_dir = os.getenv("HONEYTRAP_DATA_DIR", raw_data.get("data_dir", "data"))
    db_path = os.getenv("HONEYTRAP_DB_PATH", raw_data.get("db_path", "data/honeytrap.db"))

    # SSH config
    ssh_raw = raw_data.get("ssh", {}) if isinstance(raw_data.get("ssh"), dict) else {}
    ssh_enabled = _str_to_bool(os.getenv("HONEYTRAP_SSH_ENABLED", ssh_raw.get("enabled", True)))
    ssh_port = int(os.getenv("HONEYTRAP_SSH_PORT", ssh_raw.get("port", 2222)))
    ssh_host_key = os.getenv("HONEYTRAP_SSH_HOST_KEY_FILE", ssh_raw.get("host_key_file", "data/ssh_host_key"))
    ssh_banner = os.getenv("HONEYTRAP_SSH_BANNER", ssh_raw.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"))
    ssh_max_auth = int(os.getenv("HONEYTRAP_SSH_MAX_AUTH_ATTEMPTS", ssh_raw.get("max_auth_attempts", 6)))

    ssh_config = SSHConfig(
        enabled=ssh_enabled,
        port=ssh_port,
        host_key_file=ssh_host_key,
        banner=ssh_banner,
        max_auth_attempts=ssh_max_auth,
    )

    # HTTP config
    http_raw = raw_data.get("http", {}) if isinstance(raw_data.get("http"), dict) else {}
    http_enabled = _str_to_bool(os.getenv("HONEYTRAP_HTTP_ENABLED", http_raw.get("enabled", True)))
    http_port = int(os.getenv("HONEYTRAP_HTTP_PORT", http_raw.get("port", 8080)))
    http_server_header = os.getenv("HONEYTRAP_HTTP_SERVER_HEADER", http_raw.get("server_header", "Apache/2.4.54 (Ubuntu)"))

    http_config = HTTPConfig(
        enabled=http_enabled,
        port=http_port,
        server_header=http_server_header,
    )

    # FTP config
    ftp_raw = raw_data.get("ftp", {}) if isinstance(raw_data.get("ftp"), dict) else {}
    ftp_enabled = _str_to_bool(os.getenv("HONEYTRAP_FTP_ENABLED", ftp_raw.get("enabled", True)))
    ftp_port = int(os.getenv("HONEYTRAP_FTP_PORT", ftp_raw.get("port", 2121)))
    ftp_banner = os.getenv("HONEYTRAP_FTP_BANNER", ftp_raw.get("banner", "220 (vsFTPd 3.0.5)"))
    ftp_pasv_raw = os.getenv("HONEYTRAP_FTP_PASV_PORT_RANGE", ftp_raw.get("pasv_port_range", (30000, 30100)))
    ftp_pasv = _parse_port_range(ftp_pasv_raw)

    ftp_config = FTPConfig(
        enabled=ftp_enabled,
        port=ftp_port,
        banner=ftp_banner,
        pasv_port_range=ftp_pasv,
    )

    # API config
    api_raw = raw_data.get("api", {}) if isinstance(raw_data.get("api"), dict) else {}
    api_host = os.getenv("HONEYTRAP_API_HOST", api_raw.get("host", "0.0.0.0"))
    api_port = int(os.getenv("HONEYTRAP_API_PORT", api_raw.get("port", 3000)))
    cors_raw = os.getenv("HONEYTRAP_API_CORS_ORIGINS", api_raw.get("cors_origins", ["*"]))
    api_cors = _parse_cors_origins(cors_raw)

    api_config = APIConfig(
        host=api_host,
        port=api_port,
        cors_origins=api_cors,
    )

    # Geo config
    geo_raw = raw_data.get("geo", {}) if isinstance(raw_data.get("geo"), dict) else {}
    geo_enabled = _str_to_bool(os.getenv("HONEYTRAP_GEO_ENABLED", geo_raw.get("enabled", True)))
    geo_cache_ttl = int(os.getenv("HONEYTRAP_GEO_CACHE_TTL", geo_raw.get("cache_ttl", 86400)))

    geo_config = GeoConfig(
        enabled=geo_enabled,
        cache_ttl=geo_cache_ttl,
    )

    return Config(
        sensor_id=sensor_id,
        data_dir=data_dir,
        db_path=db_path,
        ssh=ssh_config,
        http=http_config,
        ftp=ftp_config,
        api=api_config,
        geo=geo_config,
    )
