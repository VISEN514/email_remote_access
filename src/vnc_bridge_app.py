"""The noVNC web bridge (PLAN.md 'session broker' + 'tunnel' sections).

A single self-contained Flask app that:
  - serves a plain interstitial page at GET /connect/<nonce> that reveals
    nothing but a "click to connect" button (safe for email-scanner
    prefetch -- a GET here burns nothing of value)
  - only on the interstitial's POST does it mint the REAL session token and
    hand it back as a cookie (HttpOnly, Secure, SameSite=Strict) -- the real
    token never appears in any URL, GET, or referer header
  - serves noVNC's static assets and bridges the VNC websocket, gated on
    that cookie
  - enforces idle + absolute session timeouts
  - exposes an authenticated /end-session endpoint (requires the same cookie)

This process is what gets exposed by the tunnel. It talks to TightVNC's own,
separately-running Windows service over loopback TCP -- it does not start or
stop TightVNC itself (see PLAN.md: TightVNC is a persistent service, not
started per-session).
"""
import mimetypes
import secrets
import socket
import threading
import time
from pathlib import Path

from flask import Flask, Response, abort, redirect, request
from flask_sock import Sock

ROOT = Path(__file__).resolve().parent.parent
NOVNC_DIR = ROOT / "novnc"

COOKIE_NAME = "session_token"


class VncBridgeApp:
    def __init__(self, vnc_host: str, vnc_port: int, idle_timeout_seconds: int, absolute_timeout_seconds: int):
        if not NOVNC_DIR.exists():
            raise RuntimeError(
                f"{NOVNC_DIR} not found. Clone noVNC there first: "
                f"git clone https://github.com/novnc/noVNC {NOVNC_DIR}"
            )
        self.vnc_host = vnc_host
        self.vnc_port = vnc_port
        self.idle_timeout_seconds = idle_timeout_seconds
        self.absolute_timeout_seconds = absolute_timeout_seconds

        self.nonce = secrets.token_urlsafe(24)  # low-value, appears in the emailed URL
        self._real_token = None  # minted only on successful POST, never in a URL
        self._nonce_consumed = False
        self._created_at = time.time()
        self._last_activity = time.time()
        self._ended = False
        self._lock = threading.Lock()

        self.app = Flask(__name__)
        self.sock = Sock(self.app)
        self._register_routes()

    # -- lifecycle -----------------------------------------------------
    @property
    def ended(self) -> bool:
        return self._ended

    def touch(self):
        self._last_activity = time.time()

    def is_expired(self) -> bool:
        now = time.time()
        idle_expired = now - self._last_activity > self.idle_timeout_seconds
        absolute_expired = now - self._created_at > self.absolute_timeout_seconds
        return idle_expired or absolute_expired

    def end(self):
        self._ended = True

    # -- auth ------------------------------------------------------------
    def _valid_cookie(self) -> bool:
        token = request.cookies.get(COOKIE_NAME)
        return bool(token) and self._real_token is not None and secrets.compare_digest(token, self._real_token)

    # -- routes ------------------------------------------------------------
    def _register_routes(self):
        app = self.app

        @app.after_request
        def no_referrer(resp):
            resp.headers["Referrer-Policy"] = "no-referrer"
            return resp

        @app.route("/connect/<nonce>", methods=["GET"])
        def interstitial(nonce):
            # Safe for prefetch: reveals nothing but a button. Doesn't consume
            # the nonce and doesn't touch the real token.
            if self._ended or self.is_expired():
                return Response("This access link has expired.", status=410)
            if not secrets.compare_digest(nonce, self.nonce):
                abort(404)
            return Response(
                f"""<!doctype html><html><body>
                <form method="POST" action="/connect/{nonce}">
                  <button type="submit">Click to connect</button>
                </form>
                </body></html>""",
                mimetype="text/html",
            )

        @app.route("/connect/<nonce>", methods=["POST"])
        def consume_nonce(nonce):
            if self._ended or self.is_expired():
                return Response("This access link has expired.", status=410)
            if not secrets.compare_digest(nonce, self.nonce):
                abort(404)
            with self._lock:
                if self._nonce_consumed:
                    return Response("This link has already been used.", status=410)
                self._nonce_consumed = True
                self._real_token = secrets.token_urlsafe(32)
            self.touch()
            # "path" tells noVNC's ui.js where to open the websocket, but it
            # resolves that value as a RELATIVE URL against the current
            # page (novnc/app/ui.js: `new URL(path, location.href)`) -- and
            # since this page is served at /vnc/vnc.html, a bare "ws"
            # resolves to /vnc/ws, not the /ws route this app actually
            # registers. Confirmed via field testing: a raw script hitting
            # /ws directly connects fine, while a real browser following
            # noVNC's own relative-path logic gets "Failed to connect to
            # server" because /vnc/ws doesn't exist. A leading "/" makes it
            # resolve as an absolute path instead, landing on the correct
            # route regardless of what page served it.
            resp = redirect("/vnc/vnc.html?path=%2Fws&autoconnect=true&resize=scale")
            resp.set_cookie(
                COOKIE_NAME,
                self._real_token,
                httponly=True,
                secure=True,
                samesite="Strict",
                max_age=self.absolute_timeout_seconds,
            )
            return resp

        @app.route("/vnc/<path:filename>")
        def novnc_static(filename):
            if not self._valid_cookie() or self._ended or self.is_expired():
                abort(403)
            self.touch()
            full_path = (NOVNC_DIR / filename).resolve()
            if NOVNC_DIR.resolve() not in full_path.parents and full_path != NOVNC_DIR.resolve():
                abort(404)
            if not full_path.exists():
                abort(404)
            # Flask's Response() defaults to text/html when no mimetype is
            # given -- every asset (CSS, JS, PNG icons) was being served as
            # text/html, which browsers correctly refuse to apply as a
            # stylesheet or render as an image (confirmed via field
            # testing: unstyled page, broken icons, "noVNC encountered an
            # error" banner stuck visible because the CSS that would have
            # hidden it never applied). guess_type falls back to
            # application/octet-stream for anything unrecognized, which is
            # still safe (browser won't misinterpret it as something else).
            content_type, _ = mimetypes.guess_type(str(full_path))
            return Response(full_path.read_bytes(), mimetype=content_type or "application/octet-stream")

        @app.route("/end-session", methods=["POST"])
        def end_session():
            if not self._valid_cookie():
                abort(403)
            self.end()
            return Response("Session ended.", status=200)

        @self.sock.route("/ws")
        def ws_bridge(ws):
            if not self._valid_cookie() or self._ended or self.is_expired():
                ws.close()
                return
            self.touch()
            # is_expired is rechecked on every pump iteration inside the
            # bridge (not just at connect time) -- otherwise an open
            # websocket would never be cut off by idle/absolute timeout as
            # long as SOME traffic kept flowing, defeating both expiries.
            _bridge_websocket_to_vnc(
                ws, self.vnc_host, self.vnc_port, on_activity=self.touch, is_expired=self.is_expired
            )


def _bridge_websocket_to_vnc(ws, vnc_host: str, vnc_port: int, on_activity, is_expired):
    sock_ = socket.create_connection((vnc_host, vnc_port), timeout=5)
    sock_.settimeout(1)
    stop = threading.Event()

    def pump_tcp_to_ws():
        try:
            while not stop.is_set():
                if is_expired():
                    break
                try:
                    data = sock_.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                on_activity()
                ws.send(data)
        except Exception:
            pass
        finally:
            stop.set()

    reader = threading.Thread(target=pump_tcp_to_ws, daemon=True)
    reader.start()

    try:
        while not stop.is_set():
            if is_expired():
                break
            data = ws.receive(timeout=1)
            if data is None:
                continue
            on_activity()
            sock_.sendall(data if isinstance(data, bytes) else data.encode())
    except Exception:
        pass
    finally:
        stop.set()
        sock_.close()
        try:
            ws.close()
        except Exception:
            pass
