"""GeoIP Lookup Service for HoneyTrap.

Queries ip-api.com (free tier) with rate-limiting, local memory caching,
and handling of private/bogon IP addresses.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class GeoResult:
    """Geographic information for an IP address."""
    ip: str
    country: str = "Unknown"
    country_code: str = "XX"
    city: str = "Unknown"
    lat: float = 0.0
    lon: float = 0.0
    isp: str = "Unknown"
    org: str = "Unknown"
    as_number: str = "Unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "lat": self.lat,
            "lon": self.lon,
            "isp": self.isp,
            "org": self.org,
            "as_number": self.as_number,
        }


class GeoIPLookup:
    """Asynchronous GeoIP resolver with TTL caching."""

    def __init__(self, enabled: bool = True, cache_ttl: int = 86400) -> None:
        self.enabled = enabled
        self.cache_ttl = cache_ttl
        # IP -> (timestamp, GeoResult)
        self._cache: dict[str, tuple[float, GeoResult | None]] = {}
        self._session: aiohttp.ClientSession | None = None
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()

    def _is_private_or_special(self, ip_str: str) -> bool:
        """Check if IP is loopback, private, or invalid."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            )
        except ValueError:
            return True

    async def lookup(self, ip: str) -> GeoResult | None:
        """Lookup GeoIP data for a given IP."""
        if not self.enabled or not ip:
            return None

        clean_ip = ip.strip()
        if self._is_private_or_special(clean_ip):
            return GeoResult(
                ip=clean_ip,
                country="Private Network",
                country_code="LAN",
                city="Local",
                lat=0.0,
                lon=0.0,
                isp="Local Network",
                org="Private",
                as_number="N/A",
            )

        now = time.time()
        # Check cache
        if clean_ip in self._cache:
            ts, res = self._cache[clean_ip]
            if now - ts < self.cache_ttl:
                return res

        async with self._lock:
            # Re-check inside lock
            if clean_ip in self._cache:
                ts, res = self._cache[clean_ip]
                if now - ts < self.cache_ttl:
                    return res

            # Rate limit: ensure at least 1.5s between requests to ip-api.com free tier (45 req/min)
            elapsed = now - self._last_request_time
            if elapsed < 1.4:
                await asyncio.sleep(1.4 - elapsed)

            result = await self._fetch_remote(clean_ip)
            self._last_request_time = time.time()
            self._cache[clean_ip] = (self._last_request_time, result)
            return result

    async def _fetch_remote(self, ip: str) -> GeoResult | None:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,isp,org,as"
        try:
            if self._session is None or self._session.closed:
                timeout = aiohttp.ClientTimeout(total=5.0)
                self._session = aiohttp.ClientSession(timeout=timeout)

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        return GeoResult(
                            ip=ip,
                            country=data.get("country", "Unknown"),
                            country_code=data.get("countryCode", "XX"),
                            city=data.get("city", "Unknown"),
                            lat=float(data.get("lat", 0.0)),
                            lon=float(data.get("lon", 0.0)),
                            isp=data.get("isp", "Unknown"),
                            org=data.get("org", "Unknown"),
                            as_number=data.get("as", "Unknown"),
                        )
                elif resp.status == 429:
                    logger.warning("GeoIP rate limit hit for ip-api.com")
        except Exception as exc:
            logger.debug("GeoIP lookup failed for %s: %s", ip, exc)

        return None

    async def close(self) -> None:
        """Close client session."""
        if self._session and not self._session.closed:
            await self._session.close()
