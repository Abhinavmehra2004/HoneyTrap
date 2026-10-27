"""HoneyTrap — Main entry point.

Starts all honeypot services, the analysis pipeline, and the API server.
"""

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from honeytrap.config import load_config
from honeytrap.events import EventBus
from honeytrap.store import Store
from honeytrap.analysis.mitre import MITREMapper
from honeytrap.analysis.ioc_extractor import IOCExtractor
from honeytrap.analysis.geo import GeoIPLookup
from honeytrap.honeypots.ssh_honeypot import SSHHoneypot
from honeytrap.honeypots.http_honeypot import HTTPHoneypot
from honeytrap.honeypots.ftp_honeypot import FTPHoneypot
from honeytrap.api.server import create_app


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(name)-20s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("honeytrap")

BANNER = r"""
  _   _                        _____                 
 | | | | ___  _ __   ___ _   _|_   _| __ __ _ _ __  
 | |_| |/ _ \| '_ \ / _ \ | | | | || '__/ _` | '_ \ 
 |  _  | (_) | | | |  __/ |_| | | || | | (_| | |_) |
 |_| |_|\___/|_| |_|\___|\__, | |_||_|  \__,_| .__/ 
                          |___/                |_|    
  Multi-Protocol Honeypot Network
"""


async def analysis_pipeline(
    event_bus: EventBus,
    store: Store,
    mitre: MITREMapper,
    ioc_extractor: IOCExtractor,
    geo: GeoIPLookup,
) -> None:
    """Subscribe to events and run analysis (MITRE mapping, IOC extraction, GeoIP)."""
    queue: asyncio.Queue = asyncio.Queue()

    async def _handler(event):
        await queue.put(event)

    event_bus.subscribe(_handler)
    logger.info("Analysis pipeline started")

    while True:
        event = await queue.get()
        try:
            # MITRE ATT&CK mapping
            techniques = mitre.analyze_event(event)
            event.mitre_techniques = techniques

            # GeoIP lookup
            geo_result = await geo.lookup(event.source_ip)
            if geo_result:
                event.geo = {
                    "country": geo_result.country,
                    "country_code": geo_result.country_code,
                    "city": geo_result.city,
                    "lat": geo_result.lat,
                    "lon": geo_result.lon,
                    "isp": geo_result.isp,
                    "org": geo_result.org,
                    "as_number": geo_result.as_number,
                }

            # IOC extraction
            iocs = ioc_extractor.extract_from_event(event)
            for ioc in iocs:
                await store.save_ioc(ioc)

            # Persist event
            await store.save_event(event)

        except Exception:
            logger.exception("Analysis pipeline error for event %s", event.id)


async def main() -> None:
    print(BANNER)

    config_path = os.environ.get("HONEYTRAP_CONFIG", "config.yaml")
    config = load_config(config_path)

    # Ensure data directories exist
    Path(config.data_dir).mkdir(parents=True, exist_ok=True)
    Path(f"{config.data_dir}/sessions").mkdir(parents=True, exist_ok=True)
    Path(f"{config.data_dir}/uploads").mkdir(parents=True, exist_ok=True)

    # Initialize core components
    store = Store(config.db_path)
    await store.init_db()

    event_bus = EventBus()
    mitre = MITREMapper()
    ioc_extractor = IOCExtractor()
    geo = GeoIPLookup(enabled=config.geo.enabled, cache_ttl=config.geo.cache_ttl)

    # Start analysis pipeline
    analysis_task = asyncio.create_task(
        analysis_pipeline(event_bus, store, mitre, ioc_extractor, geo)
    )

    # Start honeypots
    honeypots = []

    if config.ssh.enabled:
        ssh = SSHHoneypot(config.ssh, event_bus, config.sensor_id, config.data_dir)
        honeypots.append(ssh)
        asyncio.create_task(ssh.start())
        logger.info("SSH honeypot enabled on port %d", config.ssh.port)

    if config.http.enabled:
        http = HTTPHoneypot(config.http, event_bus, config.sensor_id)
        honeypots.append(http)
        asyncio.create_task(http.start())
        logger.info("HTTP honeypot enabled on port %d", config.http.port)

    if config.ftp.enabled:
        ftp = FTPHoneypot(config.ftp, event_bus, config.sensor_id, config.data_dir)
        honeypots.append(ftp)
        asyncio.create_task(ftp.start())
        logger.info("FTP honeypot enabled on port %d", config.ftp.port)

    # Start API server
    app = create_app(config, event_bus, store, mitre, ioc_extractor, geo)

    import uvicorn

    api_config = uvicorn.Config(
        app,
        host=config.api.host,
        port=config.api.port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(api_config)

    logger.info("Dashboard available at http://%s:%d", config.api.host, config.api.port)

    # Handle shutdown
    shutdown_event = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    # Run API server (blocks until shutdown)
    server_task = asyncio.create_task(server.serve())

    await shutdown_event.wait()

    # Graceful shutdown
    logger.info("Shutting down honeypots...")
    for hp in honeypots:
        try:
            await hp.stop()
        except Exception:
            logger.exception("Error stopping honeypot")

    analysis_task.cancel()
    server.should_exit = True
    await server_task

    logger.info("HoneyTrap stopped")


def run() -> None:
    """CLI entry point."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
