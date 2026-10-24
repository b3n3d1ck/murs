"""A small, local HTTP app used as a test target.

It is intentionally simple and runs only on 127.0.0.1. It exposes pages, links,
a login form, a multipart upload endpoint, an access-controlled path, and
soft-404 behaviour (unknown paths return 200 with a generic body) so discovery
and upload logic can be exercised deterministically without any third party.
"""

from __future__ import annotations

import threading
from email.parser import BytesParser
from email.policy import default as email_default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX = b"""<!doctype html><html><head><title>Fixture App</title></head>
<body><h1>Fixture</h1>
<a href="/about">About</a>
<a href="/login">Login</a>
<a href="/upload">Upload</a>
<a href="/secret">Secret</a>
<a href="https://external.example/off">off-scope</a>
<form action="/search" method="get"><input name="q"></form>
</body></html>"""

UPLOAD_PAGE = b"""<!doctype html><html><head><title>Upload</title></head>
<body><form action="/upload" method="post" enctype="multipart/form-data">
<input type="file" name="file"><input type="submit"></form></body></html>"""

LOGIN_PAGE = b"""<!doctype html><html><head><title>Login</title></head>
<body><form action="/login" method="post">
<input name="user"><input name="pass" type="password"></form></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "FixtureHTTP/1.0"
    stored: dict[str, bytes] = {}
    stored_protected: dict[str, bytes] = {}
    stored_stripped: dict[str, bytes] = {}
    stored_hidden: dict[str, bytes] = {}  # stored but never served anywhere

    def log_message(self, *args):  # silence
        pass

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(200, INDEX)
        if path == "/about":
            return self._send(200, b"<title>About</title><p>about page</p>")
        if path == "/login":
            return self._send(200, LOGIN_PAGE)
        if path == "/upload":
            return self._send(200, UPLOAD_PAGE)
        if path == "/secret":
            return self._send(401, b"<title>401</title>auth required",
                              extra={"WWW-Authenticate": "Basic"})
        if path == "/redirect-in":
            return self._send(302, b"", extra={"Location": "/about"})
        if path == "/redirect-out":
            return self._send(302, b"", extra={"Location": "https://external.example/x"})
        if path.startswith("/uploads/"):
            name = path[len("/uploads/"):]
            if name in type(self).stored:
                # serve raw bytes as text/plain (fixture is "safe" by default)
                return self._send(200, type(self).stored[name], ctype="text/plain")
            return self._send(404, b"<title>404</title>no file")
        if path.startswith("/protected-uploads/"):
            name = path[len("/protected-uploads/"):]
            if name in type(self).stored_protected:
                # stored but always access-controlled
                return self._send(401, b"auth required",
                                  extra={"WWW-Authenticate": "Basic"})
            return self._send(404, b"no file")
        if path.startswith("/stripped-uploads/"):
            name = path[len("/stripped-uploads/"):]
            if name in type(self).stored_stripped:
                import re as _re
                raw = type(self).stored_stripped[name]
                # simulate server-side processing that removes PHP tags WITHOUT
                # emitting our marker (interpretation we cannot confirm executed)
                processed = _re.sub(rb"<\?php.*?\?>", b"", raw, flags=_re.DOTALL)
                return self._send(200, processed, ctype="text/html")
            return self._send(404, b"no file")
        # soft-404: unknown paths return 200 with a stable generic body
        return self._send(200, b"<title>Not Found</title><p>page not found</p>")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        if path == "/login":
            return self._send(200, b"<title>Login</title>invalid credentials")
        name, data = _parse_first_file(self.headers.get("Content-Type", ""), raw)
        if path == "/upload":
            if name is None:
                return self._send(400, b"no file")
            safe = name.replace("/", "_").replace("\\", "_")
            type(self).stored[safe] = data
            return self._send(200, f"<title>ok</title>stored at /uploads/{safe}".encode())
        if path == "/upload-reject":
            if name is None:
                return self._send(400, b"no file")
            ext = name.rsplit(".", 1)[-1].lower()
            if ext in ("php", "phtml", "php5", "phar") or b"<?php" in data:
                return self._send(422, b"rejected: file type not allowed")
            safe = name.replace("/", "_")
            type(self).stored[safe] = data
            return self._send(200, f"stored at /uploads/{safe}".encode())
        if path == "/upload-protected":
            if name is None:
                return self._send(400, b"no file")
            safe = name.replace("/", "_")
            type(self).stored_protected[safe] = data
            return self._send(200, f"stored at /protected-uploads/{safe}".encode())
        if path == "/upload-strip":
            if name is None:
                return self._send(400, b"no file")
            safe = name.replace("/", "_")
            type(self).stored_stripped[safe] = data
            return self._send(200, f"stored at /stripped-uploads/{safe}".encode())
        if path == "/upload-nolocation":
            if name is None:
                return self._send(400, b"no file")
            # stored, but never served and never disclosed
            type(self).stored_hidden[name.replace("/", "_")] = data
            return self._send(200, b"upload received")
        return self._send(404, b"no such endpoint")


def _parse_first_file(content_type: str, raw: bytes):
    if "multipart/form-data" not in content_type:
        return None, b""
    header = b"Content-Type: " + content_type.encode() + b"\r\n\r\n"
    msg = BytesParser(policy=email_default).parsebytes(header + raw)
    for part in msg.iter_parts():
        if part.get_filename():
            payload = part.get_payload(decode=True) or b""
            return part.get_filename(), payload
    return None, b""


class FixtureServer:
    """Context manager that starts the fixture on a random localhost port."""

    def __init__(self):
        # reset stored files per server instance
        _Handler.stored = {}
        _Handler.stored_protected = {}
        _Handler.stored_stripped = {}
        _Handler.stored_hidden = {}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_address[1]
        self.host = "127.0.0.1"
        self._thread = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "FixtureServer":
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=3)
