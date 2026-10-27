"""HTTP Honeypot simulating vulnerable web applications (WordPress, phpMyAdmin, env leaks)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from aiohttp import web

from honeytrap.events import EventBus, EventType
from honeytrap.honeypots.base import BaseHoneypot

logger = logging.getLogger(__name__)

WP_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; Corporate Blog &#8212; WordPress</title>
<style>
body { background: #f0f0f1; font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif; margin: 0; padding: 8% 0 0; }
#login { width: 320px; margin: auto; padding: 26px 24px 46px; background: #fff; border: 1px solid #c3c4c7; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
.login h1 { text-align: center; margin-bottom: 24px; }
.login label { font-size: 14px; line-height: 1.5; color: #3c434a; }
.login input[type=text], .login input[type=password] { font-size: 24px; line-height: 1.33333333; width: 100%; padding: 3px 5px; margin: 2px 6px 16px 0; border: 1px solid #8c8f94; box-sizing: border-box; }
.login input[type=submit] { background: #2271b1; border-color: #2271b1; color: #fff; text-decoration: none; text-shadow: none; min-height: 32px; line-height: 2.30769231; padding: 0 12px; font-size: 13px; cursor: pointer; border-width: 1px; border-style: solid; border-radius: 3px; float: right; }
</style>
</head>
<body class="login js login-action-login wp-core-ui">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p>
        <label for="user_login">Username or Email Address</label>
        <input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" />
    </p>
    <div class="user-pass-wrap">
        <label for="user_pass">Password</label>
        <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" autocomplete="current-password" />
    </div>
    <p class="submit">
        <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
    </p>
</form>
</div>
</body>
</html>
"""

PMA_HTML = """<!DOCTYPE HTML>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<title>phpMyAdmin 5.2.1</title>
<style>
body { font-family: sans-serif; background: #f3f3f3; padding: 50px 0; text-align: center; }
.box { width: 360px; margin: 0 auto; background: #fff; border: 1px solid #ccc; padding: 20px; text-align: left; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h2 { margin-top: 0; color: #333; }
label { display: block; margin: 10px 0 5px; color: #555; }
input[type=text], input[type=password] { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ccc; }
input[type=submit] { margin-top: 15px; background: #0073aa; color: #fff; border: none; padding: 8px 15px; cursor: pointer; }
</style>
</head>
<body>
<div class="box">
<h2>Welcome to phpMyAdmin</h2>
<form method="post" action="/phpmyadmin/index.php">
<label for="input_username">Username:</label>
<input type="text" name="pma_username" id="input_username">
<label for="input_password">Password:</label>
<input type="password" name="pma_password" id="input_password">
<input type="submit" value="Log in">
</form>
</div>
</body>
</html>
"""

DEFAULT_APACHE_HTML = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Apache2 Ubuntu Default Page: It works</title>
<style type="text/css">
body { background-color: #eee; font-family: sans-serif; padding: 2em; }
.content { background: #fff; padding: 2em; border: 1px solid #ccc; max-width: 800px; margin: 0 auto; }
</style>
</head>
<body>
<div class="content">
<h1>Apache2 Ubuntu Default Page</h1>
<p>It works!</p>
<p>This is the default welcome page used to test the correct operation of the Apache2 server.</p>
</div>
</body>
</html>
"""


class HTTPHoneypot(BaseHoneypot):
    """HTTP Honeypot exposing deceptive attack surfaces."""

    def __init__(self, config: Any, event_bus: EventBus, sensor_id: str = "honeytrap-01") -> None:
        super().__init__(config, event_bus, sensor_id)
        self.port = getattr(config, "port", 8080)
        self.server_header = getattr(config, "server_header", "Apache/2.4.54 (Ubuntu)")
        self.runner: web.AppRunner | None = None

    async def _handle_request(self, request: web.Request) -> web.Response:
        peer_ip = request.remote or "unknown"
        # Avoid local proxy loop
        peer_port = 0
        path = request.path
        method = request.method
        headers = dict(request.headers)

        session_id = await self.create_session(peer_ip, peer_port, "http")

        # Capture POST body credentials
        body_text = ""
        post_data = {}
        username = None
        password = None

        if method == "POST":
            try:
                post_data = await request.post()
                # Common credential fields in WordPress, phpMyAdmin, and generic forms
                for u_key in ("log", "pma_username", "username", "user", "email"):
                    if u_key in post_data:
                        username = str(post_data[u_key])
                        break
                for p_key in ("pwd", "pma_password", "password", "pass"):
                    if p_key in post_data:
                        password = str(post_data[p_key])
                        break
            except Exception:
                try:
                    body_text = await request.text()
                except Exception:
                    pass

        # Emit HTTP_REQUEST event
        await self.emit_event(
            session_id=session_id,
            event_type=EventType.HTTP_REQUEST,
            source_ip=peer_ip,
            source_port=peer_port,
            protocol="http",
            data={
                "method": method,
                "path": path,
                "headers": headers,
                "user_agent": headers.get("User-Agent", ""),
                "host": headers.get("Host", ""),
                "query": dict(request.query),
            },
        )

        # Emit AUTH_ATTEMPT if credentials captured
        if username or password:
            await self.emit_event(
                session_id=session_id,
                event_type=EventType.AUTH_ATTEMPT,
                source_ip=peer_ip,
                source_port=peer_port,
                protocol="http",
                data={
                    "username": username or "",
                    "password": password or "",
                    "path": path,
                    "success": False,
                },
            )

        await self.end_session(session_id)

        # Prepare default headers
        resp_headers = {
            "Server": self.server_header,
            "X-Powered-By": "PHP/8.1.2-1ubuntu2.14",
        }

        # Response routing
        if path in ("/wp-login.php", "/wp-login"):
            return web.Response(text=WP_LOGIN_HTML, content_type="text/html", headers=resp_headers)

        if path.startswith("/wp-admin"):
            raise web.HTTPFound("/wp-login.php")

        if path in ("/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/"):
            return web.Response(text=PMA_HTML, content_type="text/html", headers=resp_headers)

        if path in ("/.env", "/.env.local", "/.git/config"):
            fake_env = (
                "APP_ENV=production\n"
                "APP_DEBUG=false\n"
                "APP_KEY=base64:9D3e8aZ182FbcjL81q0AOp=\n"
                "DB_HOST=127.0.0.1\n"
                "DB_DATABASE=corporate_db\n"
                "DB_USERNAME=root\n"
                "DB_PASSWORD=SecretPassword987!\n"
            )
            return web.Response(text=fake_env, content_type="text/plain", headers=resp_headers)

        if path == "/robots.txt":
            robots = "User-agent: *\nDisallow: /wp-admin/\nDisallow: /phpmyadmin/\nDisallow: /admin/\nDisallow: /backup.sql\n"
            return web.Response(text=robots, content_type="text/plain", headers=resp_headers)

        if path in ("/admin", "/admin/", "/administrator", "/login"):
            return web.Response(text=WP_LOGIN_HTML, content_type="text/html", headers=resp_headers)

        if path == "/":
            return web.Response(text=DEFAULT_APACHE_HTML, content_type="text/html", headers=resp_headers)

        return web.Response(
            text="<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML 2.0//EN'>\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>",
            status=404,
            content_type="text/html",
            headers=resp_headers,
        )

    async def start(self) -> None:
        """Start the aiohttp web server."""
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handle_request)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "0.0.0.0", self.port)
        await site.start()
        logger.info("HTTP Honeypot started on port %d", self.port)

    async def stop(self) -> None:
        if self.runner:
            await self.runner.cleanup()
