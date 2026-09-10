import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

with patch("vnc_bridge_app.NOVNC_DIR") as mock_dir:
    mock_dir.exists.return_value = True
    from vnc_bridge_app import VncBridgeApp, _bridge_websocket_to_vnc


class TestSessionExpiry(unittest.TestCase):
    def _make_bridge(self, idle=999, absolute=999):
        with patch("vnc_bridge_app.NOVNC_DIR") as mock_dir:
            mock_dir.exists.return_value = True
            return VncBridgeApp("127.0.0.1", 5900, idle, absolute)

    def test_not_expired_initially(self):
        bridge = self._make_bridge()
        self.assertFalse(bridge.is_expired())

    def test_absolute_timeout_expires_even_with_recent_activity(self):
        bridge = self._make_bridge(idle=999, absolute=0)
        bridge.touch()  # simulate fresh activity
        time.sleep(0.05)
        self.assertTrue(bridge.is_expired())

    def test_idle_timeout_expires_without_activity(self):
        bridge = self._make_bridge(idle=0, absolute=999)
        time.sleep(0.05)
        self.assertTrue(bridge.is_expired())


class TestWebsocketPumpRespectsExpiry(unittest.TestCase):
    def test_pump_loop_exits_promptly_once_is_expired_returns_true(self):
        # Regression test for the bug where the pump loop never rechecked
        # expiry once a websocket was open, so a session with ongoing
        # traffic could never be cut off by idle/absolute timeout.
        ws = MagicMock()
        ws.receive.return_value = None  # never sends anything, just polls

        fake_sock = MagicMock()
        fake_sock.recv.side_effect = TimeoutError()  # never receives either

        expired = {"value": False}

        def is_expired():
            return expired["value"]

        with patch("vnc_bridge_app.socket.create_connection", return_value=fake_sock):
            import threading

            def flip_expired_soon():
                time.sleep(0.1)
                expired["value"] = True

            threading.Thread(target=flip_expired_soon, daemon=True).start()

            start = time.time()
            _bridge_websocket_to_vnc(ws, "127.0.0.1", 5900, on_activity=lambda: None, is_expired=is_expired)
            elapsed = time.time() - start

        # Should exit shortly after expiry flips, not hang indefinitely.
        self.assertLess(elapsed, 2.0)
        fake_sock.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
