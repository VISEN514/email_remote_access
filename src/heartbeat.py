import logging
import os
import socket
import time
import urllib.request

logger = logging.getLogger("heartbeat")

# PLAN.md section 4: Task Scheduler's "run as soon as possible after a
# missed start" covers a laptop that was merely asleep/off at 6am, but a
# laptop off for DAYS could miss rotation entirely and silently -- this
# threshold is what makes that visible. ~30h gives real margin above one
# missed-then-caught-up daily cycle (24h) without false-tripping on normal
# day-to-day timing jitter.
PHRASE_ROTATION_OVERDUE_SECONDS = 30 * 3600


class Heartbeat:
    """Reports a poll cycle as successful only if BOTH the watcher completed
    its cycle AND TightVNC's loopback port is still accepting connections --
    a green mail-watcher heartbeat alone doesn't prove the actual remote
    access capability is alive (PLAN.md Monitoring section).

    Known, named limitation: this is a bare TCP connect check, not an RFB
    handshake probe -- it doesn't prove TightVNC has completed the protocol
    handshake, only that its listener accepts a connection. Deferred as
    unnecessary v1 complexity; still catches crash/stopped-service/unbound-port,
    the much more common failure modes.

    v2 adds a THIRD, independent check: is the daily phrase rotation overdue
    (PLAN.md section 4)? This is detection-only, by design -- it makes a
    stale rotation visible, but does not itself force a rotation or lock
    anything out.

    The security-levels feature adds a FOURTH, independent check: has
    security level 1 (the allow-list-dropped, weaker authentication mode)
    been continuously active longer than expected? Also detection-only --
    addresses the realistic failure mode of flipping to level 1 for one
    temporary need and forgetting to flip back (PLAN.md "Notification and
    staleness signal").
    """

    def __init__(
        self,
        vnc_host: str,
        vnc_port: int,
        phrase_path: str,
        security_level_store=None,
        l1_max_continuous_hours: float = 24,
        external_ping_url: str = "",
    ):
        self.vnc_host = vnc_host
        self.vnc_port = vnc_port
        self.phrase_path = phrase_path
        self.security_level_store = security_level_store
        self.l1_max_continuous_seconds = l1_max_continuous_hours * 3600
        self.external_ping_url = external_ping_url

    def vnc_reachable(self) -> bool:
        try:
            with socket.create_connection((self.vnc_host, self.vnc_port), timeout=2):
                return True
        except OSError:
            return False

    def phrase_rotation_overdue(self) -> bool:
        try:
            mtime = os.path.getmtime(self.phrase_path)
        except OSError:
            # No phrase file at all is a much worse problem than "overdue"
            # (PhraseManager creates it on first construction), but report
            # it as overdue rather than raising -- heartbeat reporting must
            # never itself crash the watcher's poll loop.
            return True
        return (time.time() - mtime) > PHRASE_ROTATION_OVERDUE_SECONDS

    def security_level_1_too_long(self) -> bool:
        if self.security_level_store is None:
            return False
        if self.security_level_store.get_level() != 1:
            return False
        since = self.security_level_store.get_since()
        if not since:
            return False
        return (time.time() - since) > self.l1_max_continuous_seconds

    def report_cycle(self, watcher_ok: bool):
        vnc_ok = self.vnc_reachable()
        rotation_overdue = self.phrase_rotation_overdue()
        level_1_too_long = self.security_level_1_too_long()

        if not watcher_ok:
            state = "unhealthy: watcher poll cycle failed"
        elif not vnc_ok:
            state = "degraded: watcher alive, VNC service unreachable"
        elif rotation_overdue:
            state = "degraded: phrase rotation overdue (>30h since last change)"
        elif level_1_too_long:
            state = "degraded: security level 1 has been active too long"
        else:
            state = "healthy"

        logger.info("heartbeat: %s", state)
        if self.external_ping_url and watcher_ok and vnc_ok and not rotation_overdue and not level_1_too_long:
            try:
                urllib.request.urlopen(self.external_ping_url, timeout=5)
            except OSError:
                logger.warning("External heartbeat ping failed")
        return state
