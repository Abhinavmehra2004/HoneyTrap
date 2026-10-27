"""SSH Honeypot implementation using asyncssh.

Provides a fake shell environment with 25+ realistic Unix commands,
logs credentials and commands, and records sessions in asciicast v2 format.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from honeytrap.events import EventBus, EventType
from honeytrap.honeypots.base import BaseHoneypot

logger = logging.getLogger(__name__)


class FakeShell:
    """Emulates a realistic Linux root/user shell."""

    def __init__(self, username: str = "root", hostname: str = "ubuntu-server") -> None:
        self.username = username
        self.hostname = hostname
        self.cwd = "/root" if username == "root" else f"/home/{username}"
        self.start_time = time.time()
        self.history: list[str] = []

    def prompt(self) -> str:
        symbol = "#" if self.username == "root" else "$"
        short_dir = "~" if self.cwd in ("/root", f"/home/{self.username}") else self.cwd
        return f"{self.username}@{self.hostname}:{short_dir}{symbol} "

    def execute(self, command_line: str) -> str | None:
        """Execute a simulated command and return terminal output, or None on exit."""
        cmd_str = command_line.strip()
        if not cmd_str:
            return ""

        self.history.append(cmd_str)
        tokens = cmd_str.split()
        cmd = tokens[0]
        args = tokens[1:]

        if cmd in ("exit", "logout", "quit"):
            return None

        if cmd == "whoami":
            return self.username

        if cmd == "id":
            if self.username == "root":
                return "uid=0(root) gid=0(root) groups=0(root)"
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),4(adm),27(sudo)"

        if cmd == "hostname":
            return self.hostname

        if cmd == "uname":
            if "-a" in args:
                return "Linux ubuntu-server 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
            if "-r" in args:
                return "5.15.0-88-generic"
            return "Linux"

        if cmd == "pwd":
            return self.cwd

        if cmd == "cd":
            target = args[0] if args else ("~" if self.username != "root" else "/root")
            if target == "~":
                self.cwd = "/root" if self.username == "root" else f"/home/{self.username}"
            elif target.startswith("/"):
                self.cwd = target
            elif target == "..":
                parts = self.cwd.rstrip("/").split("/")
                self.cwd = "/".join(parts[:-1]) or "/"
            else:
                self.cwd = f"{self.cwd.rstrip('/')}/{target}"
            return ""

        if cmd == "ls":
            flags = [a for a in args if a.startswith("-")]
            is_long = any("l" in f for f in flags)
            is_all = any("a" in f for f in flags)

            if is_long:
                lines = [
                    "total 36",
                    "drwx------  5 root root 4096 Oct 12 09:15 .",
                    "drwxr-xr-x 19 root root 4096 Sep 20 14:02 ..",
                    "-rw-------  1 root root  842 Oct 15 11:22 .bash_history",
                    "-rw-r--r--  1 root root 3106 Oct 15 10:12 .bashrc",
                    "drwx------  2 root root 4096 Sep 20 14:05 .ssh",
                    "-rw-r--r--  1 root root  161 Jul  9  2019 .profile",
                    "-rw-r--r--  1 root root 1204 Oct 10 18:04 config.yaml",
                    "-rw-r--r--  1 root root  482 Oct 11 08:33 backup.sh",
                ]
                return "\n".join(lines)
            return ".bashrc  .profile  .ssh  backup.sh  config.yaml"

        if cmd == "cat":
            if not args:
                return ""
            target = args[0]
            if "/etc/passwd" in target:
                return (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                    "sync:x:4:65534:sync:/bin:/bin/sync\n"
                    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
                    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
                    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin"
                )
            if "/etc/shadow" in target:
                if self.username != "root":
                    return "cat: /etc/shadow: Permission denied"
                return (
                    "root:$6$rounds=4096$salt$hashedpasswordstring:19600:0:99999:7:::\n"
                    "ubuntu:$6$rounds=4096$salt$userhashedpassword:19600:0:99999:7:::"
                )
            if "/etc/issue" in target or "/etc/os-release" in target:
                return 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"'
            return f"cat: {target}: No such file or directory"

        if cmd in ("ifconfig", "ip"):
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 192.168.1.150  netmask 255.255.255.0  broadcast 192.168.1.255\n"
                "        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n"
                "        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n"
                "        RX packets 145022  bytes 18940212 (18.9 MB)\n"
                "        TX packets 98311  bytes 12401823 (12.4 MB)\n\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                "        inet 127.0.0.1  netmask 255.0.0.0\n"
                "        loop  txqueuelen 1000  (Local Loopback)"
            )

        if cmd == "netstat":
            return (
                "Active Internet connections (only servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      824/sshd: /usr/sbin\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      912/apache2\n"
                "tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      845/vsftpd\n"
                "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1014/mysqld"
            )

        if cmd == "ps":
            return (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root           1  0.0  0.1 168432 11840 ?        Ss   Oct10   0:03 /sbin/init\n"
                "root         824  0.0  0.0  15884  7200 ?        Ss   Oct10   0:00 /usr/sbin/sshd -D\n"
                "root         845  0.0  0.0   8120  3400 ?        Ss   Oct10   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf\n"
                "www-data     912  0.0  0.2 214500 18200 ?        S    Oct10   0:01 /usr/sbin/apache2 -k start\n"
                "mysql       1014  0.1  2.5 1421000 205400 ?      Ssl  Oct10   1:12 /usr/sbin/mysqld\n"
                f"{self.username:<10}  2144  0.0  0.0  14560  4800 pts/0    Ss   12:00   0:00 -bash\n"
                f"{self.username:<10}  2201  0.0  0.0  18900  3200 pts/0    R+   12:05   0:00 ps {' '.join(args)}"
            )

        if cmd == "uptime":
            return " 12:05:14 up 14 days,  3:22,  1 user,  load average: 0.08, 0.04, 0.01"

        if cmd == "df":
            return (
                "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
                "udev             4012920        0   4012920   0% /dev\n"
                "tmpfs             808200     1420    806780   1% /run\n"
                "/dev/sda1       40864380 18451200  20311244  48% /\n"
                "tmpfs            4041000        0   4041000   0% /dev/shm"
            )

        if cmd == "free":
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:         8082004     1428512     4821040       18420     1832452     6354120\n"
                "Swap:        2097148           0     2097148"
            )

        if cmd == "history":
            return "\n".join(f"  {i+1}  {h}" for i, h in enumerate(self.history))

        if cmd in ("wget", "curl"):
            url = args[0] if args else "http://example.com"
            filename = url.split("/")[-1] or "index.html"
            if cmd == "wget":
                return (
                    f"--2023-10-15 12:06:01--  {url}\n"
                    f"Resolving ... connected.\n"
                    f"HTTP request sent, awaiting response... 200 OK\n"
                    f"Length: 4096 (4.0K)\n"
                    f"Saving to: '{filename}'\n\n"
                    f"{filename}          100%[===================>]   4.00K  --.-KB/s    in 0.01s\n\n"
                    f"2023-10-15 12:06:01 (400 KB/s) - '{filename}' saved [4096/4096]"
                )
            return f"Downloading {url} ... 100% saved."

        if cmd in ("echo", "touch", "mkdir", "rm", "cp", "mv", "chmod", "chown"):
            return ""

        return f"-bash: {cmd}: command not found"


class AsciicastRecorder:
    """Records terminal sessions in asciicast v2 format."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.start_time = time.time()
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        self.file = open(filepath, "w", encoding="utf-8")
        header = {
            "version": 2,
            "width": 80,
            "height": 24,
            "timestamp": int(self.start_time),
            "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
        }
        self.file.write(json.dumps(header) + "\n")
        self.file.flush()

    def record(self, event_type: str, data: str) -> None:
        """Record input or output chunk."""
        rel_time = round(time.time() - self.start_time, 4)
        entry = [rel_time, event_type, data]
        self.file.write(json.dumps(entry) + "\n")
        self.file.flush()

    def close(self) -> None:
        if not self.file.closed:
            self.file.close()


class SSHHoneypot(BaseHoneypot):
    """Full-featured SSH Honeypot."""

    def __init__(
        self,
        config: Any,
        event_bus: EventBus,
        sensor_id: str = "honeytrap-01",
        data_dir: str = "data",
    ) -> None:
        super().__init__(config, event_bus, sensor_id)
        self.data_dir = data_dir
        self.port = getattr(config, "port", 2222)
        self.server: Any = None
        self._stopped = False

    async def start(self) -> None:
        """Start the SSH honeypot server."""
        try:
            import asyncssh

            host_key_path = getattr(self.config, "host_key_file", f"{self.data_dir}/ssh_host_key")
            Path(host_key_path).parent.mkdir(parents=True, exist_ok=True)
            if not os.path.exists(host_key_path):
                key = asyncssh.generate_private_key("ssh-rsa")
                with open(host_key_path, "wb") as f:
                    f.write(key.export_private_key())

            hp = self

            class HoneypotSSHServer(asyncssh.SSHServer):
                def connection_made(self, conn: Any) -> None:
                    self._conn = conn
                    peer = conn.get_extra_info("peername")
                    self.peer_ip = peer[0] if peer else "unknown"
                    self.peer_port = peer[1] if peer else 0
                    self.session_id = ""

                def password_auth_supported(self) -> bool:
                    return True

                def validate_password(self, username: str, password: str) -> bool:
                    # Log credentials and always succeed
                    loop = asyncio.get_event_loop()
                    loop.create_task(self._record_auth(username, password))
                    return True

                async def _record_auth(self, username: str, password: str) -> None:
                    if not self.session_id:
                        self.session_id = await hp.create_session(self.peer_ip, self.peer_port, "ssh")
                    await hp.emit_event(
                        session_id=self.session_id,
                        event_type=EventType.AUTH_ATTEMPT,
                        source_ip=self.peer_ip,
                        source_port=self.peer_port,
                        protocol="ssh",
                        data={"username": username, "password": password, "success": True},
                    )

            async def handle_client(process: Any) -> None:
                peer = process.get_extra_info("peername")
                peer_ip = peer[0] if peer else "unknown"
                peer_port = peer[1] if peer else 0
                username = process.get_extra_info("username") or "root"

                session_id = await hp.create_session(peer_ip, peer_port, "ssh")
                cast_path = f"{hp.data_dir}/sessions/{session_id}.cast"
                recorder = AsciicastRecorder(cast_path)
                shell = FakeShell(username=username)

                banner = f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\n"
                process.stdout.write(banner)
                recorder.record("o", banner)

                try:
                    while not hp._stopped:
                        prompt = shell.prompt()
                        process.stdout.write(prompt)
                        recorder.record("o", prompt)

                        line = await process.stdin.readline()
                        if not line:
                            break

                        cmd_line = line.strip("\r\n")
                        recorder.record("i", line)

                        await hp.emit_event(
                            session_id=session_id,
                            event_type=EventType.COMMAND,
                            source_ip=peer_ip,
                            source_port=peer_port,
                            protocol="ssh",
                            data={"command": cmd_line, "username": username},
                        )

                        output = shell.execute(cmd_line)
                        if output is None:
                            goodbye = "logout\r\nConnection to honeypot closed.\r\n"
                            process.stdout.write(goodbye)
                            recorder.record("o", goodbye)
                            break

                        if output:
                            formatted = output.replace("\n", "\r\n") + "\r\n"
                            process.stdout.write(formatted)
                            recorder.record("o", formatted)

                except Exception as exc:
                    logger.debug("SSH session exception: %s", exc)
                finally:
                    recorder.close()
                    await hp.end_session(session_id)
                    process.exit(0)

            self.server = await asyncssh.create_server(
                HoneypotSSHServer,
                "",
                self.port,
                server_host_keys=[host_key_path],
                process_factory=handle_client,
            )
            logger.info("SSH Honeypot started on port %d", self.port)

        except Exception as exc:
            logger.warning("Failed to start asyncssh server (%s); starting simulated TCP listener", exc)
            # Lightweight raw socket fallback for test environments or non-root port bindings
            async def fallback_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                peer = writer.get_extra_info("peername")
                peer_ip = peer[0] if peer else "unknown"
                peer_port = peer[1] if peer else 0
                session_id = await self.create_session(peer_ip, peer_port, "ssh")
                writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
                await writer.drain()
                await self.end_session(session_id)
                writer.close()

            try:
                self.server = await asyncio.start_server(fallback_handler, "0.0.0.0", self.port)
            except Exception as e:
                logger.error("SSH fallback server error: %s", e)

    async def stop(self) -> None:
        self._stopped = True
        if self.server:
            if hasattr(self.server, "close"):
                self.server.close()
                if hasattr(self.server, "wait_closed"):
                    await self.server.wait_closed()
