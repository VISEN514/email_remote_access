import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import session_broker  # noqa: E402
from state_store import StateStore  # noqa: E402


def _listen_on_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s, s.getsockname()[1]


class TestSessionBrokerStartupFailureCleanup(unittest.TestCase):
    """Regression tests for round-2 finding #1: a failure in the nonce-read
    or port-readiness step (not just tunnel.start()) previously left the
    bridge subprocess orphaned instead of terminated."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.session_config = {
            "vnc_host": "127.0.0.1",
            "vnc_port": 5900,
            "idle_timeout_minutes": 15,
            "absolute_timeout_minutes": 60,
            "local_web_port_range": [21000, 21010],
            "state_path": str(Path(self.tmpdir.name) / "state.json"),
        }

    def tearDown(self):
        self.tmpdir.cleanup()

    def _make_broker(self):
        state = StateStore(self.session_config["state_path"])
        return session_broker.SessionBroker(self.session_config, {"provider": "cloudflare"}, state=state)

    def test_nonce_timeout_terminates_bridge_process(self):
        broker = self._make_broker()

        fake_proc = MagicMock()
        fake_proc.stdout = ["not a nonce line\n"]  # never yields NONCE=
        fake_proc.poll.return_value = None  # looks alive
        fake_proc.wait.return_value = None

        with patch.object(session_broker.subprocess, "Popen", return_value=fake_proc):
            with patch.object(broker, "_read_nonce_from_bridge", side_effect=TimeoutError("no nonce")):
                with self.assertRaises(TimeoutError):
                    broker.start_session()

        fake_proc.terminate.assert_called_once()

    def test_bridge_process_dying_right_before_identity_capture_still_gets_cleaned_up(self):
        # Regression test for round-9 finding: ProcessIdentity.capture() was
        # called AFTER the try/except that terminates the bridge on any
        # earlier failure -- so if the bridge process died in the gap
        # between being confirmed alive and capture() actually running
        # (capture() itself raises psutil.NoSuchProcess for a dead PID),
        # the exception propagated uncaught, skipping cleanup entirely and
        # leaving an untracked, unrecorded, unsupervised process running --
        # the exact failure mode the round-8 fix existed to eliminate, just
        # relocated to a narrower race window instead of a process restart.
        broker = self._make_broker()

        fake_proc = MagicMock()
        fake_proc.poll.return_value = None
        fake_proc.wait.return_value = None

        fake_tunnel = MagicMock()
        fake_tunnel.start.return_value = "https://example.trycloudflare.com"
        fake_tunnel.pid = None  # simulates it having already died

        with patch.object(session_broker.subprocess, "Popen", return_value=fake_proc):
            with patch.object(broker, "_read_nonce_from_bridge", return_value="fake-nonce"):
                with patch.object(broker, "_wait_for_local_port", return_value=None):
                    with patch.object(session_broker, "build_tunnel_provider", return_value=fake_tunnel):
                        with patch.object(
                            session_broker.ProcessIdentity,
                            "capture",
                            side_effect=RuntimeError("process disappeared right before capture"),
                        ):
                            with self.assertRaises(RuntimeError):
                                broker.start_session()

        # The bridge process must still have been terminated, not leaked,
        # despite the exception happening AFTER the tunnel already started.
        fake_proc.terminate.assert_called_once()
        fake_tunnel.stop.assert_called_once()

    def test_state_update_failing_after_processes_are_live_still_terminates_them(self):
        # Regression test for round-10 finding: an earlier fix closed the
        # race where ProcessIdentity.capture() could raise on a dying
        # process, but the try/except boundary still stopped BEFORE
        # self.state.update() -- so a disk-write failure at exactly that
        # point (bridge and tunnel both alive and identity-captured, state
        # write itself failing) left both processes running with no state
        # record and no watchdog. The whole remainder of start_session() is
        # now inside one try/except; this proves a state.update() failure
        # specifically still triggers full cleanup.
        broker = self._make_broker()

        fake_proc = MagicMock()
        fake_proc.poll.return_value = None
        fake_proc.wait.return_value = None

        fake_tunnel = MagicMock()
        fake_tunnel.start.return_value = "https://example.trycloudflare.com"
        fake_tunnel.pid = None

        with patch.object(session_broker.subprocess, "Popen", return_value=fake_proc):
            with patch.object(broker, "_read_nonce_from_bridge", return_value="fake-nonce"):
                with patch.object(broker, "_wait_for_local_port", return_value=None):
                    with patch.object(session_broker, "build_tunnel_provider", return_value=fake_tunnel):
                        with patch.object(
                            session_broker.ProcessIdentity, "capture", return_value=MagicMock(to_dict=lambda: {})
                        ):
                            # Two DIFFERENT exception instances, not one
                            # reused for both calls -- the first is the
                            # "real" failure (recording the session), the
                            # second is the cleanup handler's own attempt to
                            # clear state afterward. Distinguishing them
                            # proves the ORIGINAL exception is what actually
                            # propagates, not whichever one happened to run
                            # last -- a single shared exception instance
                            # would make this indistinguishable from a bug
                            # where the cleanup's own error masks the
                            # original one.
                            original_error = OSError("disk full: recording session")
                            cleanup_error = OSError("disk full: clearing state during cleanup")
                            with patch.object(
                                broker.state, "update", side_effect=[original_error, cleanup_error]
                            ):
                                with self.assertRaises(OSError) as ctx:
                                    broker.start_session()
                                self.assertIs(
                                    ctx.exception,
                                    original_error,
                                    "the ORIGINAL exception must propagate, not the cleanup handler's own error",
                                )

        fake_proc.terminate.assert_called_once()
        fake_tunnel.stop.assert_called_once()

    def test_drain_thread_construction_failure_right_after_popen_still_terminates_bridge(self):
        # Regression test for round-11 finding: the try/except had been
        # widened twice (rounds 9 and 10) to cover steps AFTER the bridge
        # process was spawned, but subprocess.Popen() itself and the
        # stdout-drain thread's construction/start still ran BEFORE the try
        # block began. A threading.Thread(...) failure right after a
        # successful Popen() (this test simulates it failing at
        # construction time; a failure inside the later .start() call would
        # hit the exact same exception path, since both are inside the same
        # try block now) left a live, running bridge process with no
        # cleanup, no state record, and no watchdog -- the 4th occurrence of
        # the same "exception boundary one step too narrow" bug in this
        # method across rounds 8-10. The structural fix moves Popen() and
        # the thread construction/start INSIDE the try block; this proves
        # it for the first threading.Thread(...) call the method makes (the
        # drain thread) -- the watchdog thread's own construction, later in
        # the same try block, is never reached in this test because control
        # jumps to `except` as soon as this first Thread(...) call raises.
        broker = self._make_broker()

        fake_proc = MagicMock()
        fake_proc.poll.return_value = None
        fake_proc.wait.return_value = None

        with patch.object(session_broker.subprocess, "Popen", return_value=fake_proc):
            with patch.object(
                session_broker.threading, "Thread", side_effect=RuntimeError("can't construct new thread")
            ):
                with self.assertRaises(RuntimeError):
                    broker.start_session()

        # The bridge process that Popen() DID successfully create must
        # still have been terminated, not leaked.
        fake_proc.terminate.assert_called_once()

    def test_port_readiness_timeout_terminates_bridge_process(self):
        broker = self._make_broker()

        fake_proc = MagicMock()
        fake_proc.poll.return_value = None
        fake_proc.wait.return_value = None

        with patch.object(session_broker.subprocess, "Popen", return_value=fake_proc):
            with patch.object(broker, "_read_nonce_from_bridge", return_value="fake-nonce"):
                with patch.object(broker, "_wait_for_local_port", side_effect=TimeoutError("never listened")):
                    with self.assertRaises(TimeoutError):
                        broker.start_session()

        fake_proc.terminate.assert_called_once()
        # bridge_proc reference must be cleared so a later has_active_session
        # check / restart attempt doesn't trip over a stale handle
        self.assertIsNone(broker._bridge_proc)


class TestDrainThreadAndNonceCapture(unittest.TestCase):
    """Exercises the REAL _drain_bridge_stdout + _read_nonce_from_bridge
    together against a fake process stdout, rather than mocking out the
    method under test -- a prior round's tests mocked
    _read_nonce_from_bridge itself, which meant they couldn't have caught a
    bug in its actual body or in the drain thread it depends on."""

    def _fake_proc_with_lines(self, lines):
        proc = MagicMock()
        proc.stdout = iter(lines)
        proc.poll.return_value = None
        return proc

    def test_nonce_found_among_many_filler_lines(self):
        broker = session_broker.SessionBroker.__new__(session_broker.SessionBroker)
        broker._captured_nonce = None
        filler = [f"log line {i}\n" for i in range(50)]
        lines = filler[:10] + ["NONCE=abc123\n"] + filler[10:]
        broker._bridge_proc = self._fake_proc_with_lines(lines)

        broker._drain_bridge_stdout()  # run synchronously for determinism
        self.assertEqual(broker._captured_nonce, "abc123")

        nonce = broker._read_nonce_from_bridge()
        self.assertEqual(nonce, "abc123")

    def test_only_first_nonce_line_is_captured(self):
        broker = session_broker.SessionBroker.__new__(session_broker.SessionBroker)
        broker._captured_nonce = None
        broker._bridge_proc = self._fake_proc_with_lines(["NONCE=first\n", "NONCE=second\n"])

        broker._drain_bridge_stdout()
        self.assertEqual(broker._captured_nonce, "first")

    def test_nonce_read_races_drain_thread_correctly_when_run_concurrently(self):
        # Runs the drain thread for real (in a background thread, as
        # start_session actually does) racing against _read_nonce_from_bridge
        # polling concurrently -- verifies no lost/garbled nonce under real
        # thread interleaving, not just sequential execution.
        broker = session_broker.SessionBroker.__new__(session_broker.SessionBroker)
        broker._captured_nonce = None

        def slow_lines():
            for i in range(20):
                yield f"log line {i}\n"
                time.sleep(0.001)
            yield "NONCE=raced-value\n"
            for i in range(20):
                yield f"trailing log {i}\n"

        proc = MagicMock()
        proc.stdout = slow_lines()
        proc.poll.return_value = None
        broker._bridge_proc = proc

        t = threading.Thread(target=broker._drain_bridge_stdout, daemon=True)
        t.start()

        nonce = broker._read_nonce_from_bridge()
        self.assertEqual(nonce, "raced-value")
        t.join(timeout=2)


class TestWaitForLocalPort(unittest.TestCase):
    def test_returns_once_port_is_listening(self):
        broker = session_broker.SessionBroker.__new__(session_broker.SessionBroker)
        sock_, port = _listen_on_free_port()
        try:
            broker._wait_for_local_port(port, timeout_seconds=2)  # should not raise
        finally:
            sock_.close()

    def test_times_out_if_nothing_ever_listens(self):
        broker = session_broker.SessionBroker.__new__(session_broker.SessionBroker)
        # Pick a port nothing is bound to.
        with self.assertRaises(TimeoutError):
            broker._wait_for_local_port(21099, timeout_seconds=0.5)


class TestPidReuseSafeReconciliation(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_path = str(Path(self.tmpdir.name) / "state.json")
        self.session_config = {
            "vnc_host": "127.0.0.1",
            "vnc_port": 5900,
            "idle_timeout_minutes": 15,
            "absolute_timeout_minutes": 60,
            "local_web_port_range": [21000, 21010],
            "state_path": self.state_path,
        }

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_no_active_session_record_is_fine(self):
        state = StateStore(self.state_path)
        broker = session_broker.SessionBroker(self.session_config, {"provider": "cloudflare"}, state=state)
        self.assertFalse(broker.has_active_session())

    def test_stale_record_with_dead_pid_is_cleared(self):
        store = StateStore(self.state_path)
        # A PID essentially guaranteed not to correspond to a real running
        # process with a matching create_time/exe (impossible-looking values).
        store.update(
            lambda d: {
                **d,
                "active_session": {
                    "broker_identity": {"pid": 999999, "create_time": 1.0, "exe": "nonexistent.exe"},
                    "started_at": time.time(),
                },
            }
        )
        broker = session_broker.SessionBroker(self.session_config, {"provider": "cloudflare"}, state=store)
        self.assertFalse(broker.has_active_session())
        # Reconciliation should have cleared the stale record entirely.
        self.assertIsNone(store.read().get("active_session"))

    def test_record_matching_a_real_still_alive_orphan_is_terminated_not_adopted(self):
        # Regression test for round-8 finding: an earlier version of
        # reconciliation "adopted" a still-alive session found in state
        # left by a prior process instance -- but a fresh SessionBroker
        # instance has no way to reconstruct the Popen handles needed to
        # actually manage that session going forward, so "adopted" really
        # meant "has_active_session() reports True forever while the real
        # bridge/tunnel run completely unmanaged, invisible to any
        # watchdog, and silently un-torn-down by a later end_session()
        # call (which only touches self._bridge_proc/self._tunnel, both
        # None for an 'adopted' session)". The fix: never adopt: always
        # terminate whatever's found (via a real orphaned subprocess here,
        # never the test process itself -- adoption used to be simulated
        # with os.getpid(), which would be actively dangerous to reuse now
        # that reconciliation actually calls terminate on a match).
        import subprocess as sp

        from process_identity import ProcessIdentity

        orphan = sp.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            identity = ProcessIdentity.capture(orphan.pid)
            store = StateStore(self.state_path)
            store.update(
                lambda d: {
                    **d,
                    "active_session": {"broker_identity": identity.to_dict(), "started_at": time.time()},
                }
            )

            broker = session_broker.SessionBroker(self.session_config, {"provider": "cloudflare"}, state=store)

            # The orphan must actually be terminated by reconciliation...
            orphan.wait(timeout=5)
            self.assertIsNotNone(orphan.poll(), "orphaned process was 'adopted' instead of terminated")

            # ...and the record must be cleared, not left claiming an
            # active session this fresh instance has no way to manage.
            self.assertFalse(broker.has_active_session())
            self.assertIsNone(store.read().get("active_session"))
        finally:
            if orphan.poll() is None:
                orphan.kill()

    def test_orphaned_tunnel_process_is_also_terminated_on_reconciliation(self):
        # The bridge isn't the only thing that can be left running after a
        # crash -- the tunnel process (a PUBLICLY REACHABLE URL into the
        # loopback VNC bridge) matters even more. Confirms a persisted
        # tunnel_identity is also found and terminated.
        import subprocess as sp

        from process_identity import ProcessIdentity

        orphan_bridge = sp.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        orphan_tunnel = sp.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            bridge_identity = ProcessIdentity.capture(orphan_bridge.pid)
            tunnel_identity = ProcessIdentity.capture(orphan_tunnel.pid)
            store = StateStore(self.state_path)
            store.update(
                lambda d: {
                    **d,
                    "active_session": {
                        "broker_identity": bridge_identity.to_dict(),
                        "tunnel_identity": tunnel_identity.to_dict(),
                        "started_at": time.time(),
                    },
                }
            )

            session_broker.SessionBroker(self.session_config, {"provider": "cloudflare"}, state=store)

            orphan_bridge.wait(timeout=5)
            orphan_tunnel.wait(timeout=5)
            self.assertIsNotNone(orphan_bridge.poll())
            self.assertIsNotNone(orphan_tunnel.poll(), "orphaned TUNNEL process was left running")
        finally:
            for p in (orphan_bridge, orphan_tunnel):
                if p.poll() is None:
                    p.kill()


class TestEndSessionPartialFailureIsolation(unittest.TestCase):
    """Regression test for round-7 finding: end_session() used to run its
    steps sequentially with no isolation -- if tunnel.stop() raised,
    _terminate_bridge() never ran (leaking the bridge process) AND the
    state-store write clearing active_session never ran either, leaving
    has_active_session() reporting True forever with no automatic recovery.
    Uses a REAL SessionBroker (not a mock standing in for it), with a real
    subprocess and a tunnel whose .stop() is made to raise, to prove the
    ACTUAL object's behavior post-fix -- not just that some mock was called."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_path = str(Path(self.tmpdir.name) / "state.json")
        self.session_config = {
            "vnc_host": "127.0.0.1",
            "vnc_port": 5900,
            "idle_timeout_minutes": 15,
            "absolute_timeout_minutes": 60,
            "local_web_port_range": [21000, 21010],
            "state_path": self.state_path,
        }

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_state_is_cleared_and_bridge_terminated_even_when_tunnel_stop_raises(self):
        state = StateStore(self.state_path)
        broker = session_broker.SessionBroker(self.session_config, {"provider": "cloudflare"}, state=state)

        # Simulate a broker that has an active session: a real subprocess
        # (so _terminate_bridge does real work) and a fake tunnel whose
        # stop() raises (the exact failure mode from the round-7 finding).
        import subprocess as sp

        real_proc = sp.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        broker._bridge_proc = real_proc

        broken_tunnel = MagicMock()
        broken_tunnel.stop.side_effect = RuntimeError("tunnel provider blew up")
        broker._tunnel = broken_tunnel

        broker._watchdog_stop = threading.Event()

        from process_identity import ProcessIdentity

        identity = ProcessIdentity.capture(real_proc.pid)
        state.update(
            lambda d: {**d, "active_session": {"broker_identity": identity.to_dict(), "started_at": time.time()}}
        )

        with self.assertRaises(RuntimeError):
            broker.end_session()

        # Despite tunnel.stop() raising: the bridge subprocess must still
        # have been terminated (not leaked)...
        real_proc.wait(timeout=5)
        self.assertIsNotNone(real_proc.poll(), "bridge subprocess was leaked after tunnel.stop() raised")

        # ...and the state store must still have been cleared, so
        # has_active_session() is truthful afterward rather than reporting
        # a session that looks active forever with no recovery path.
        self.assertIsNone(state.read().get("active_session"))
        self.assertFalse(broker.has_active_session())


class TestSharedStateStoreAcrossConcurrentWriters(unittest.TestCase):
    """Regression test for round-6 finding: SessionBroker used to construct
    its OWN StateStore pointed at the same file main.py's lockout/handled-ids
    store used -- two different in-process locks guarding one file provide
    NO protection against each other, so a broker-internal write (e.g. from
    the watchdog thread's end_session()) could silently clobber a concurrent
    lockout/handled-ids write. Verifies that many concurrent writers sharing
    ONE StateStore instance never lose an update, the way two separate
    instances on the same file could."""

    def test_concurrent_updates_from_many_threads_never_lose_a_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(str(Path(tmp) / "state.json"))

            def writer(n):
                store.update(lambda d: {**d, f"key_{n}": n})

            threads = [threading.Thread(target=writer, args=(i,)) for i in range(50)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            data = store.read()
            for i in range(50):
                self.assertEqual(data.get(f"key_{i}"), i, f"write for key_{i} was lost to a race")


class TestOnSessionEndCallback(unittest.TestCase):
    """PLAN.md section 8: every logout sends a confirmation email once
    teardown completes, stating whether it was clean or partial -- wired
    via SessionBroker's on_session_end callback."""

    def _broker(self, tmp, on_session_end):
        state = StateStore(str(Path(tmp) / "state.json"))
        session_config = {
            "vnc_host": "127.0.0.1",
            "vnc_port": 5900,
            "idle_timeout_minutes": 15,
            "absolute_timeout_minutes": 60,
            "local_web_port_range": [21100, 21110],
            "state_path": str(Path(tmp) / "state.json"),
        }
        return session_broker.SessionBroker(
            session_config, {"provider": "cloudflare"}, state=state, on_session_end=on_session_end
        )

    def test_clean_teardown_fires_callback_with_clean_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            on_session_end = MagicMock()
            broker = self._broker(tmp, on_session_end)
            broker.end_session()
            on_session_end.assert_called_once_with(clean=True)

    def test_failed_teardown_fires_callback_with_clean_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            on_session_end = MagicMock()
            broker = self._broker(tmp, on_session_end)
            broken_tunnel = MagicMock()
            broken_tunnel.stop.side_effect = RuntimeError("tunnel blew up")
            broker._tunnel = broken_tunnel

            with self.assertRaises(RuntimeError):
                broker.end_session()

            on_session_end.assert_called_once_with(clean=False)

    def test_callback_exception_does_not_mask_teardown_or_prevent_state_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            on_session_end = MagicMock(side_effect=RuntimeError("notifier is down"))
            broker = self._broker(tmp, on_session_end)
            broker.end_session()  # must not raise -- callback failure is swallowed
            self.assertFalse(broker.has_active_session())

    def test_no_callback_configured_is_a_safe_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker = self._broker(tmp, on_session_end=None)
            broker.end_session()  # must not raise


if __name__ == "__main__":
    unittest.main()
