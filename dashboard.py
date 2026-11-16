"""
Serve the security dashboard locally and open it in the browser.

Usage:
    python dashboard.py            # view existing reports
    python dashboard.py --scan     # run run_all.py first, then view

Security model (the reports contain AWS account details):
  * Listens on 127.0.0.1 only.
  * Serves an explicit allowlist of files, never the project directory.
  * One-time launch token -> HttpOnly, SameSite=Strict session cookie.
    Report data is refused without that cookie.
  * Host header check (blocks DNS-rebinding), GET-only.
  * Strict Content-Security-Policy with a per-response nonce, no third-party
    resources, and no-store caching.
"""

import hmac
import secrets
import subprocess
import sys
import threading
import webbrowser
from email.utils import formatdate
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

BASE_DIR = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8000
COOKIE = "cg_session"

PAGE = "dashboard.html"
REPORT_FILES = [
    "scan_report.json",
    "nacl_report.json",
    "iam_report.json",
    "s3_report.json",
    "cloudtrail_report.json",
    "guardduty_report.json",
    "config_report.json",
    "security_analysis_report.json",
]

# URL path -> file on disk. Anything not listed here is a 404.
ROUTES = {"/": BASE_DIR / PAGE, "/" + PAGE: BASE_DIR / PAGE}
ROUTES.update({f"/reports/{name}": BASE_DIR / "reports" / name for name in REPORT_FILES})

CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".json": "application/json; charset=utf-8"}


class State:
    """Launch token (single use) and the sessions it creates."""

    def __init__(self):
        self.launch_token = secrets.token_urlsafe(32)
        self.sessions = set()
        self.lock = threading.Lock()

    def redeem(self, token):
        with self.lock:
            if self.launch_token and token and hmac.compare_digest(token, self.launch_token):
                self.launch_token = None  # one use only
                session = secrets.token_urlsafe(32)
                self.sessions.add(session)
                return session
        return None

    def valid(self, session):
        with self.lock:
            return any(hmac.compare_digest(session, s) for s in self.sessions) if session else False


class Handler(BaseHTTPRequestHandler):
    server_version = "SecurityScanner"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002 - keep terminal quiet
        return

    # ---- helpers -------------------------------------------------------
    def _headers(self, nonce=None):
        script = f"script-src 'nonce-{nonce}'" if nonce else "script-src 'none'"
        style = f"style-src 'nonce-{nonce}'" if nonce else "style-src 'none'"
        self.send_header(
            "Content-Security-Policy",
            f"default-src 'none'; {script}; {style}; img-src 'self' data:; connect-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def _send(self, status, body=b"", ctype="text/plain; charset=utf-8", nonce=None, extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self._headers(nonce)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _session(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = SimpleCookie(raw)
        except Exception:
            return None
        morsel = jar.get(COOKIE)
        return morsel.value if morsel else None

    # ---- request handling ---------------------------------------------
    def do_GET(self):
        if self.headers.get("Host", "") not in (f"{HOST}:{PORT}", f"localhost:{PORT}"):
            return self._send(400, b"Bad host")

        parts = urlsplit(self.path)
        path = parts.path
        state = self.server.state

        if path == "/favicon.ico":
            return self._send(204)

        token = parse_qs(parts.query).get("t", [None])[0]
        if token:
            session = state.redeem(token)
            if not session:
                return self._send(403, b"Link expired. Run python dashboard.py again.")
            cookie = f"{COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/"
            return self._send(302, extra=[("Location", "/" + PAGE), ("Set-Cookie", cookie)])

        if not state.valid(self._session()):
            return self._send(403, b"Access denied. Start the dashboard with python dashboard.py.")

        file = ROUTES.get(path)
        if file is None:
            return self._send(404, b"Not found")
        try:
            data = file.read_bytes()
            mtime = file.stat().st_mtime
        except OSError:
            return self._send(404, b"No report available")

        ctype = CONTENT_TYPES[file.suffix]
        nonce = None
        if file.suffix == ".html":
            nonce = secrets.token_urlsafe(16)
            html = data.decode("utf-8").replace("<script>", f'<script nonce="{nonce}">').replace(
                "<style>", f'<style nonce="{nonce}">')
            data = html.encode("utf-8")
        self._send(200, data, ctype, nonce, extra=[("Last-Modified", formatdate(mtime, usegmt=True))])

    def _not_allowed(self):
        self._send(405, b"Method not allowed", extra=[("Allow", "GET")])

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _not_allowed


def make_server():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.state = State()
    url = f"http://{HOST}:{PORT}/?t={server.state.launch_token}"
    return server, url


def main():
    if "--scan" in sys.argv:
        subprocess.run([sys.executable, str(BASE_DIR / "run_all.py")], cwd=BASE_DIR)

    if not (BASE_DIR / "reports" / "security_analysis_report.json").exists():
        print("No analysis report found. Run: python dashboard.py --scan")
        return

    server, url = make_server()
    print(f"Dashboard running at http://{HOST}:{PORT}/{PAGE}  (Ctrl+C to stop)")
    print("Access is granted only to the browser window opened by this command.")
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
