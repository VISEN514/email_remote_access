"""Subprocess entrypoint for one session's noVNC bridge (see session_broker.py).

Run in its own process (not a thread) so the broker can terminate it
cleanly and unambiguously at session end, and so a bridge crash can't take
the mail watcher down with it.
"""
import logging
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vnc_bridge_app import VncBridgeApp  # noqa: E402

logger = logging.getLogger("bridge_entrypoint")


def _expiry_watchdog(bridge: "VncBridgeApp"):
    # The broker tears the whole bridge+tunnel down "by process termination"
    # (PLAN.md) -- but nothing kills this process on its own when idle/
    # absolute timeout hits unless this loop does it. Without this, the
    # Flask process (and the tunnel exposing it) would keep running
    # indefinitely after expiry, just refusing new requests -- still a
    # standing, unnecessary public endpoint.
    #
    # KNOWN, NAMED TRADEOFF: this is a hard `os._exit(0)`, not a graceful
    # shutdown -- it does not wait for the websocket pump threads in
    # vnc_bridge_app.py to notice expiry and close cleanly, or drain any
    # in-flight HTTP response. A live VNC connection open at the exact
    # moment expiry fires gets abruptly severed rather than shown a clean
    # "session ended" message. Accepted for v1: the alternative (waiting on
    # pump threads that are themselves blocked in blocking socket calls with
    # only a 1-second poll granularity) adds real shutdown-ordering
    # complexity for a cosmetic improvement only -- the session was ending
    # regardless, and the client-side noVNC UI already handles a severed
    # connection by showing its own disconnect state.
    while True:
        time.sleep(5)
        if bridge.ended or bridge.is_expired():
            logger.info("Session expired or ended -- terminating bridge process")
            os._exit(0)


def main():
    logging.basicConfig(level=logging.INFO)
    bridge = VncBridgeApp(
        vnc_host=os.environ["ERA_VNC_HOST"],
        vnc_port=int(os.environ["ERA_VNC_PORT"]),
        idle_timeout_seconds=int(os.environ["ERA_IDLE_TIMEOUT"]),
        absolute_timeout_seconds=int(os.environ["ERA_ABSOLUTE_TIMEOUT"]),
    )
    threading.Thread(target=_expiry_watchdog, args=(bridge,), daemon=True).start()

    # The parent process reads this line to learn the nonce -- do not print
    # anything before it, and flush immediately.
    print(f"NONCE={bridge.nonce}", flush=True)

    # KNOWN, NAMED LIMITATION (not silently accepted): this process is
    # directly what the Cloudflare tunnel exposes to the public internet for
    # the session's duration, and it runs on Werkzeug's development server,
    # which upstream explicitly disclaims as unfit for production (no real
    # timeout/slowloris handling). flask-sock's websocket bridging depends
    # on WSGI-level socket hijacking that only the dev server (or
    # gunicorn+eventlet/gevent) supports -- gunicorn isn't viable on Windows
    # (no fork()), and a real production-grade websocket-capable server here
    # would mean rearchitecting the bridge onto an ASGI stack (e.g. Quart),
    # which is a larger change than this build takes on. Mitigating factors
    # that make this an acceptable v1 tradeoff rather than an open hole:
    # each session is short-lived (idle/absolute timeout, single-use nonce),
    # single-connection (no concurrent sessions), and only exists behind a
    # freshly random, single-use Cloudflare hostname for that narrow window
    # -- not a standing, discoverable production endpoint under sustained
    # internet-wide load. Revisit if/when this moves beyond personal use.
    bridge.app.run(host="127.0.0.1", port=int(os.environ["ERA_PORT"]), threaded=True)


if __name__ == "__main__":
    main()
