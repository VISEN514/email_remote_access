import logging
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from process_identity import ProcessIdentity
from state_store import StateStore
from tunnel import build_tunnel_provider

logger = logging.getLogger("session_broker")

ROOT = Path(__file__).resolve().parent.parent


def _free_port(port_range) -> int:
    lo, hi = port_range
    for port in range(lo, hi):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port in range {port_range}")


class SessionBroker:
    """Starts/stops the noVNC bridge (as a subprocess) + tunnel for one
    session at a time. TightVNC itself is a persistent Windows service this
    broker never starts or stops (see PLAN.md)."""

    def __init__(self, session_config: dict, tunnel_config: dict, state: StateStore, on_session_end=None):
        """`state` MUST be the same StateStore instance used elsewhere in the
        process for the same underlying file (main.py owns creating it and
        passes it in here) -- a StateStore's atomicity guarantee comes from
        an in-process threading.Lock, which only protects against other
        holders of THAT SAME instance. Two separate StateStore objects
        pointed at the identical file (as an earlier version of this class
        did, constructing its own) have two different locks and provide
        each other no protection at all: a write from one can silently
        clobber a concurrent write from the other (e.g. this class's own
        watchdog thread calling end_session() racing against
        MailWatcher._remember_handled(), both touching the same file)."""
        self.vnc_host = session_config["vnc_host"]
        self.vnc_port = session_config["vnc_port"]
        self.idle_timeout_seconds = session_config["idle_timeout_minutes"] * 60
        self.absolute_timeout_seconds = session_config["absolute_timeout_minutes"] * 60
        self.port_range = session_config["local_web_port_range"]
        self._tunnel_config = tunnel_config
        self.state = state
        # PLAN.md section 8: every logout sends a confirmation email once
        # teardown completes, stating whether it was clean or partial.
        # Fired from end_session() below, best-effort (a callback failure
        # must not mask or interrupt teardown itself).
        self.on_session_end = on_session_end

        self._bridge_proc: subprocess.Popen | None = None
        self._tunnel = None
        self._watchdog_stop = threading.Event()
        self._lock = threading.Lock()

        self._reconcile_on_startup()

    # -- crash/restart reconciliation, PID-reuse-safe -----------------------
    def _reconcile_on_startup(self):
        """On every start, NEVER "adopt" a session record left by a prior
        process instance -- always tear it down and start clean.

        An earlier version distinguished "still alive" (adopt it) from
        "stale" (kill it) -- but "adopting" a session is a lie this class
        can't make good on: this fresh instance has no `_bridge_proc`
        Popen handle, no `_tunnel` object, and no watchdog thread for that
        old session, because none of those can be reconstructed from a bare
        PID after a restart (you cannot get a subprocess.Popen wrapping an
        arbitrary existing PID). "Adopting" just meant `has_active_session()`
        would report True forever afterward while the actual bridge +
        (crucially) the Cloudflare tunnel -- a PUBLICLY REACHABLE URL into
        the loopback VNC service -- kept running completely unmanaged: no
        watchdog to notice it should expire, and a later end_session() call
        would silently no-op on it (self._tunnel/self._bridge_proc are None)
        while still reporting success and clearing state, believing the
        orphan was cleaned up.

        The only genuinely safe behavior with what a fresh process actually
        has available is: whatever is recorded, alive or not, gets
        terminated (using ProcessIdentity's PID-reuse-safe identity check,
        so this can never kill an unrelated process that happens to reuse
        an old PID), and the record is unconditionally cleared. This is
        simpler than "adopt when possible" and, unlike it, is actually
        correct: it always ends in a state where nothing is running and
        nothing is recorded, matching each other and matching reality.
        """
        data = self.state.read()
        record = data.get("active_session")
        if not record:
            return

        bridge_identity = ProcessIdentity.from_dict(record["broker_identity"])
        if bridge_identity.is_still_this_process():
            logger.warning(
                "Found a still-running orphaned bridge process (PID %s) from a prior process "
                "instance -- terminating it rather than adopting it (this fresh instance has no "
                "way to reconstruct the handles needed to actually manage it going forward).",
                bridge_identity.pid,
            )
            bridge_identity.terminate_if_orphaned()
        else:
            logger.info("Prior bridge process record is stale (PID reused or process already gone).")

        tunnel_record = record.get("tunnel_identity")
        if tunnel_record:
            tunnel_identity = ProcessIdentity.from_dict(tunnel_record)
            if tunnel_identity.is_still_this_process():
                logger.warning(
                    "Found a still-running orphaned TUNNEL process (PID %s) from a prior process "
                    "instance -- this may be a live public URL into the loopback VNC bridge. "
                    "Terminating it.",
                    tunnel_identity.pid,
                )
                tunnel_identity.terminate_if_orphaned()

        self.state.update(lambda d: {**d, "active_session": None})

    def has_active_session(self) -> bool:
        data = self.state.read()
        record = data.get("active_session")
        if not record:
            return False
        identity = ProcessIdentity.from_dict(record["broker_identity"])
        return identity.is_still_this_process()

    # -- session lifecycle ----------------------------------------------
    def start_session(self) -> str:
        """Starts the bridge + tunnel. Returns the interstitial URL (with
        the low-value nonce, not the real session token -- see PLAN.md)."""
        with self._lock:
            if self.has_active_session():
                raise RuntimeError("A session is already active; only one at a time is supported.")

            local_port = _free_port(self.port_range)

            # STRUCTURAL fix, not another incrementally-widened try block:
            # this method went through three straight rounds of "the
            # exception boundary is one step too narrow" (round 8: adopting
            # a session with no way to manage it; round 9: a process dying
            # right before ProcessIdentity.capture(); round 10: the
            # state-store write itself failing) -- each fix just moved the
            # boundary to cover the previously-uncovered step, and each time
            # the NEXT step outside that boundary turned out to have the
            # same hazard. The actual bug was never "this one specific line
            # needs a try/except," it was "any code that can leave a live
            # process running must be inside the SAME guarded region as its
            # cleanup, with literally nothing live-process-creating outside
            # it." So: the try block now starts BEFORE the bridge process is
            # even spawned -- there is no line anywhere in this method,
            # from the moment local_port is chosen to the return statement,
            # that creates a live resource while sitting outside exception
            # handling that can clean it up. Cleanup in the except clause
            # checks what actually got created (self._bridge_proc,
            # self._tunnel may be None if the failure happened before they
            # were ever assigned -- both _terminate_bridge() and the tunnel
            # cleanup already handle a None/not-yet-set case as a no-op) so
            # this works correctly regardless of exactly which line failed.
            try:
                self._bridge_proc = subprocess.Popen(
                    [sys.executable, str(ROOT / "src" / "bridge_entrypoint.py")],
                    env={
                        **os.environ,
                        "ERA_VNC_HOST": self.vnc_host,
                        "ERA_VNC_PORT": str(self.vnc_port),
                        "ERA_IDLE_TIMEOUT": str(self.idle_timeout_seconds),
                        "ERA_ABSOLUTE_TIMEOUT": str(self.absolute_timeout_seconds),
                        "ERA_PORT": str(local_port),
                    },
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                # Drain stdout continuously in a background thread, not just
                # the one nonce line -- otherwise ongoing Flask/werkzeug
                # request logging can fill the OS pipe buffer and block the
                # child mid-session once nothing is reading from the pipe
                # anymore. The drain thread is the ONLY reader of the pipe,
                # and it is also the one that captures the nonce itself into
                # a single attribute (self._captured_nonce) the instant it
                # sees the NONCE= line -- _read_nonce_from_bridge below just
                # polls that attribute. This deliberately avoids an earlier
                # version of this fix where the drain thread appended to a
                # shared list that a second thread indexed positionally:
                # trimming that list's front (to bound memory) could shift
                # every later element left and desync the reader's position,
                # silently skipping lines. A single scalar attribute,
                # written once by the only writer and polled (not indexed)
                # by the only reader, has no such hazard.
                self._captured_nonce = None
                threading.Thread(target=self._drain_bridge_stdout, daemon=True).start()

                nonce = self._read_nonce_from_bridge()
                self._wait_for_local_port(local_port)
                self._tunnel = build_tunnel_provider(self._tunnel_config)
                public_base = self._tunnel.start(local_port)

                bridge_identity = ProcessIdentity.capture(self._bridge_proc.pid)
                # Persist the tunnel's identity too, not just the bridge's --
                # without this, a future restart's reconciliation has no PID
                # to even look for and can't clean up an orphaned tunnel
                # process at all (see _reconcile_on_startup's docstring).
                tunnel_identity = ProcessIdentity.capture(self._tunnel.pid) if self._tunnel.pid else None

                self.state.update(
                    lambda d: {
                        **d,
                        "active_session": {
                            "broker_identity": bridge_identity.to_dict(),
                            "tunnel_identity": tunnel_identity.to_dict() if tunnel_identity else None,
                            "started_at": time.time(),
                        },
                    }
                )

                self._watchdog_stop.clear()
                threading.Thread(target=self._watchdog, daemon=True).start()
            except Exception:
                # Cleans up whatever actually got created, regardless of
                # which line above failed -- both branches below are
                # already no-ops if their resource was never assigned.
                self._terminate_bridge()
                if self._tunnel:
                    try:
                        self._tunnel.stop()
                    except Exception:
                        logger.exception("tunnel.stop() also failed while cleaning up a failed start_session()")
                    self._tunnel = None
                try:
                    self.state.update(lambda d: {**d, "active_session": None})
                except Exception:
                    logger.exception("Failed to clear state during start_session() cleanup")
                raise

            return f"{public_base}/connect/{nonce}"

    def _drain_bridge_stdout(self):
        proc = self._bridge_proc
        if proc is None or proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                if self._captured_nonce is None and line.startswith("NONCE="):
                    self._captured_nonce = line.strip().split("=", 1)[1]
                logger.debug("bridge: %s", line.rstrip())
        except (ValueError, OSError):
            pass  # pipe closed as part of normal teardown

    def _wait_for_local_port(self, port: int, timeout_seconds: float = 10.0):
        """The bridge prints its nonce before Flask has necessarily finished
        binding its listening socket -- starting the tunnel immediately after
        reading the nonce line has a real ordering gap where the tunnel could
        begin forwarding before anything is listening. Poll the actual socket
        instead of trusting print-ordering as a readiness signal."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                try:
                    s.connect(("127.0.0.1", port))
                    return
                except OSError:
                    time.sleep(0.2)
        raise TimeoutError(f"Bridge never started listening on port {port}")

    def _read_nonce_from_bridge(self) -> str:
        # Polls self._captured_nonce (written exactly once, by the drain
        # thread only) rather than reading the pipe directly here -- the
        # drain thread is the sole reader of the pipe.
        deadline = time.time() + 15
        while time.time() < deadline:
            if self._captured_nonce is not None:
                return self._captured_nonce
            if self._bridge_proc.poll() is not None:
                raise RuntimeError("Bridge process exited before reporting its nonce")
            time.sleep(0.05)
        raise TimeoutError("Timed out waiting for bridge process to start")

    def end_session(self):
        """Best-effort, always-progresses teardown: each step is attempted
        independently so that one step failing (e.g. tunnel.stop() raising)
        can't skip the others. An earlier version ran these sequentially with
        no isolation -- if tunnel.stop() raised, _terminate_bridge() never
        ran (leaving the bridge process orphaned) AND the state-store write
        clearing active_session never ran either, so the system looked
        "still active" indefinitely with no automatic recovery path short of
        a manual process kill + state edit. Now: every step is attempted
        regardless of whether an earlier one failed, and the LAST thing that
        happens is always the state-store write clearing active_session --
        so even a partial failure (bridge process leaked, tunnel not fully
        torn down) still leaves has_active_session() correctly reporting
        False afterward, rather than leaving the system permanently wedged
        in a state that looks active but has no path back except manual
        intervention. Any individual step's exception is logged, not
        swallowed silently, and re-raised at the end (after every step has
        been attempted) so the caller still knows teardown wasn't clean --
        callers that need best-effort-and-keep-going (main.py's
        commit_staged failure handler) already wrap this call themselves."""
        with self._lock:
            self._watchdog_stop.set()

            errors = []
            if self._tunnel:
                try:
                    self._tunnel.stop()
                except Exception as e:
                    logger.exception("tunnel.stop() failed during end_session")
                    errors.append(e)
                finally:
                    self._tunnel = None

            try:
                self._terminate_bridge()
            except Exception as e:
                logger.exception("_terminate_bridge() failed during end_session")
                errors.append(e)

            # Always runs, even if the steps above failed -- this is what
            # keeps has_active_session() truthful afterward regardless of
            # how cleanly the underlying resources actually tore down.
            self.state.update(lambda d: {**d, "active_session": None})

            # Fired once teardown has fully completed (clean or not), always
            # -- including on the raise path below, since the caller's
            # notification should reflect what actually happened here, not
            # be skipped just because this method also re-raises. Wrapped
            # so a broken callback can't mask the original teardown errors.
            if self.on_session_end is not None:
                try:
                    self.on_session_end(clean=not errors)
                except Exception:
                    logger.exception("on_session_end callback failed")

            if errors:
                raise errors[0]

    def _terminate_bridge(self):
        if self._bridge_proc and self._bridge_proc.poll() is None:
            self._bridge_proc.terminate()
            try:
                self._bridge_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._bridge_proc.kill()
        self._bridge_proc = None

    def _watchdog(self):
        while not self._watchdog_stop.is_set():
            time.sleep(10)
            with self._lock:
                proc = self._bridge_proc
            if proc is None or proc.poll() is not None:
                self.end_session()
                return
