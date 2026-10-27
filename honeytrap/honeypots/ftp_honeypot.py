"""FTP Honeypot implementation using raw asyncio streams."""

from __future__ import annotations

import asyncio
import logging
import os
import random
from pathlib import Path
from typing import Any

from honeytrap.events import EventBus, EventType
from honeytrap.honeypots.base import BaseHoneypot

logger = logging.getLogger(__name__)


class FTPHoneypot(BaseHoneypot):
    """Asynchronous FTP Honeypot simulating vsFTPd 3.0.5."""

    def __init__(
        self,
        config: Any,
        event_bus: EventBus,
        sensor_id: str = "honeytrap-01",
        data_dir: str = "data",
    ) -> None:
        super().__init__(config, event_bus, sensor_id)
        self.data_dir = data_dir
        self.port = getattr(config, "port", 2121)
        self.banner = getattr(config, "banner", "220 (vsFTPd 3.0.5)")
        self.pasv_range = getattr(config, "pasv_port_range", (30000, 30100))
        self.server: asyncio.Server | None = None
        self._stopped = False

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle_client, "0.0.0.0", self.port)
        logger.info("FTP Honeypot started on port %d", self.port)

    async def stop(self) -> None:
        self._stopped = True
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else "unknown"
        peer_port = peer[1] if peer else 0

        session_id = await self.create_session(peer_ip, peer_port, "ftp")
        username: str | None = None
        cwd = "/"
        pasv_server: asyncio.Server | None = None
        pasv_data_future: asyncio.Future | None = None

        async def send_response(code_text: str) -> None:
            writer.write(f"{code_text}\r\n".encode("utf-8"))
            await writer.drain()

        # Send welcome banner
        await send_response(self.banner)

        try:
            while not self._stopped:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break

                raw_line = line_bytes.decode("utf-8", errors="ignore").strip()
                if not raw_line:
                    continue

                parts = raw_line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1].strip() if len(parts) > 1 else ""

                # Emit FTP command event
                await self.emit_event(
                    session_id=session_id,
                    event_type=EventType.FTP_COMMAND,
                    source_ip=peer_ip,
                    source_port=peer_port,
                    protocol="ftp",
                    data={"raw_command": raw_line, "command": cmd, "argument": arg},
                )

                if cmd == "QUIT":
                    await send_response("221 Goodbye.")
                    break

                elif cmd == "USER":
                    username = arg
                    await send_response("331 Please specify the password.")

                elif cmd == "PASS":
                    password = arg
                    await self.emit_event(
                        session_id=session_id,
                        event_type=EventType.AUTH_ATTEMPT,
                        source_ip=peer_ip,
                        source_port=peer_port,
                        protocol="ftp",
                        data={"username": username or "anonymous", "password": password, "success": True},
                    )
                    await send_response("230 Login successful.")

                elif cmd == "SYST":
                    await send_response("215 UNIX Type: L8")

                elif cmd == "PWD" or cmd == "XPWD":
                    await send_response(f'257 "{cwd}" is the current directory')

                elif cmd == "CWD":
                    cwd = arg if arg.startswith("/") else f"{cwd.rstrip('/')}/{arg}"
                    await send_response("250 Directory successfully changed.")

                elif cmd == "CDUP":
                    cwd = "/"
                    await send_response("250 Directory successfully changed.")

                elif cmd == "TYPE":
                    await send_response("200 Switching to Binary mode.")

                elif cmd == "PASV":
                    # Allocate an ephemeral port in PASV range
                    p_min, p_max = self.pasv_range
                    pasv_port = random.randint(p_min, min(p_max, p_min + 50))
                    pasv_data_future = asyncio.get_event_loop().create_future()

                    async def _pasv_conn_handler(p_reader: asyncio.StreamReader, p_writer: asyncio.StreamWriter) -> None:
                        if pasv_data_future and not pasv_data_future.done():
                            pasv_data_future.set_result((p_reader, p_writer))

                    try:
                        if pasv_server:
                            pasv_server.close()
                        pasv_server = await asyncio.start_server(_pasv_conn_handler, "0.0.0.0", pasv_port)
                        p1 = pasv_port // 256
                        p2 = pasv_port % 256
                        # Use local loopback or server IP for PASV response
                        ip_parts = "127,0,0,1"
                        await send_response(f"227 Entering Passive Mode ({ip_parts},{p1},{p2}).")
                    except Exception as exc:
                        logger.error("Failed to start PASV listener: %s", exc)
                        await send_response("425 Can't open data connection.")

                elif cmd in ("LIST", "NLST"):
                    await send_response("150 Here comes the directory listing.")
                    if pasv_data_future:
                        try:
                            p_reader, p_writer = await asyncio.wait_for(pasv_data_future, timeout=5.0)
                            listing = (
                                "-rw-r--r--    1 ftp      ftp          1024 Oct 10 12:00 backup.tar.gz\r\n"
                                "-rw-r--r--    1 ftp      ftp           512 Oct 11 08:30 credentials.txt\r\n"
                                "drwxr-xr-x    2 ftp      ftp          4096 Oct 12 14:00 confidential\r\n"
                            )
                            p_writer.write(listing.encode("utf-8"))
                            await p_writer.drain()
                            p_writer.close()
                        except Exception:
                            pass
                    await send_response("226 Directory send OK.")

                elif cmd == "RETR":
                    await send_response(f"150 Opening BINARY mode data connection for {arg}.")
                    if pasv_data_future:
                        try:
                            p_reader, p_writer = await asyncio.wait_for(pasv_data_future, timeout=5.0)
                            p_writer.write(b"SIMULATED HONEYPOT ARTIFACT\n")
                            await p_writer.drain()
                            p_writer.close()
                        except Exception:
                            pass
                    await send_response("226 Transfer complete.")

                elif cmd == "STOR":
                    await send_response(f"150 Ok to send data.")
                    upload_dir = Path(f"{self.data_dir}/uploads/{session_id}")
                    upload_dir.mkdir(parents=True, exist_ok=True)
                    target_file = upload_dir / Path(arg).name

                    captured_bytes = b""
                    if pasv_data_future:
                        try:
                            p_reader, p_writer = await asyncio.wait_for(pasv_data_future, timeout=10.0)
                            captured_bytes = await p_reader.read()
                            with open(target_file, "wb") as f:
                                f.write(captured_bytes)
                            p_writer.close()
                        except Exception as exc:
                            logger.error("Error reading uploaded FTP file: %s", exc)

                    await self.emit_event(
                        session_id=session_id,
                        event_type=EventType.FILE_UPLOAD,
                        source_ip=peer_ip,
                        source_port=peer_port,
                        protocol="ftp",
                        data={
                            "filename": arg,
                            "size_bytes": len(captured_bytes),
                            "stored_path": str(target_file),
                        },
                    )
                    await send_response("226 Transfer complete.")

                elif cmd == "SIZE":
                    await send_response("213 1024")

                elif cmd == "NOOP":
                    await send_response("200 Zzz.")

                else:
                    await send_response(f"500 Unknown command '{cmd}'.")

        except Exception as exc:
            logger.debug("FTP session exception: %s", exc)
        finally:
            if pasv_server:
                pasv_server.close()
            await self.end_session(session_id)
            writer.close()
