import sys
import tempfile
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


class TestRedirectPathIsAbsolute(unittest.TestCase):
    """Regression test for a real field-testing bug: noVNC's ui.js resolves
    the "path" query parameter as a RELATIVE URL against the current page
    (new URL(path, location.href)). Since vnc.html is served at
    /vnc/vnc.html, a bare "path=ws" resolves to /vnc/ws -- but this app's
    websocket route is registered at /ws (top-level), not /vnc/ws. A real
    browser correctly following noVNC's own relative-path logic then hits a
    route that doesn't exist and shows "Failed to connect to server",
    while a raw script hitting /ws directly (bypassing this resolution
    entirely) sees no problem -- which is exactly how this bug hid during
    initial testing. The fix: redirect with a LEADING SLASH ("/ws",
    URL-encoded as %2Fws in the query string), which resolves as an
    absolute path regardless of what page requested it."""

    def _make_bridge(self):
        with patch("vnc_bridge_app.NOVNC_DIR") as mock_dir:
            mock_dir.exists.return_value = True
            return VncBridgeApp("127.0.0.1", 5900, 999, 999)

    def test_redirect_path_param_is_absolute_not_relative(self):
        bridge = self._make_bridge()
        client = bridge.app.test_client()
        resp = client.post(f"/connect/{bridge.nonce}")
        self.assertEqual(resp.status_code, 302)
        location = resp.headers["Location"]
        # Must be an absolute-path encoding ("/ws" -> "%2Fws"), not the bare
        # "ws" that resolves relative to /vnc/vnc.html's own directory.
        self.assertIn("path=%2Fws", location)
        self.assertNotIn("path=ws&", location)


class TestStaticAssetContentType(unittest.TestCase):
    """Regression test for a real field-testing bug: novnc_static() served
    every asset via Response(bytes) with no mimetype, which Flask defaults
    to text/html -- so every CSS file, JS file, and PNG icon was served as
    text/html. Browsers correctly refuse to apply a stylesheet or render an
    image served with the wrong content-type, which is exactly what field
    testing showed: an unstyled noVNC page, broken icon images, and the
    boilerplate error banner stuck visible because the CSS that would
    normally hide it never applied."""

    def _make_bridge_with_real_assets(self, tmpdir):
        (Path(tmpdir) / "style.css").write_bytes(b"body { color: red; }")
        (Path(tmpdir) / "app.js").write_bytes(b"console.log('hi');")
        # A minimal valid PNG (1x1 transparent pixel).
        png_bytes = bytes.fromhex(
            "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753"
            "de0000000c4944415478da6360606060000000050001a5f645400000000049454e44ae426082"
        )
        (Path(tmpdir) / "icon.png").write_bytes(png_bytes)

        with patch("vnc_bridge_app.NOVNC_DIR", Path(tmpdir)):
            bridge = VncBridgeApp("127.0.0.1", 5900, 999, 999)
        # Patch the module-level NOVNC_DIR too, since novnc_static's route
        # closure reads it at request time via the module global, not via
        # the instance.
        return bridge

    def _authenticated_client(self, bridge):
        client = bridge.app.test_client()
        resp = client.post(f"/connect/{bridge.nonce}")
        self.assertEqual(resp.status_code, 302)
        return client

    def test_css_served_with_text_css_content_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("vnc_bridge_app.NOVNC_DIR", Path(tmp)):
                bridge = self._make_bridge_with_real_assets(tmp)
                client = self._authenticated_client(bridge)
                resp = client.get("/vnc/style.css")
                self.assertEqual(resp.status_code, 200)
                self.assertIn("text/css", resp.content_type)

    def test_js_served_with_javascript_content_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("vnc_bridge_app.NOVNC_DIR", Path(tmp)):
                bridge = self._make_bridge_with_real_assets(tmp)
                client = self._authenticated_client(bridge)
                resp = client.get("/vnc/app.js")
                self.assertEqual(resp.status_code, 200)
                self.assertNotIn("text/html", resp.content_type)

    def test_png_served_with_image_content_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("vnc_bridge_app.NOVNC_DIR", Path(tmp)):
                bridge = self._make_bridge_with_real_assets(tmp)
                client = self._authenticated_client(bridge)
                resp = client.get("/vnc/icon.png")
                self.assertEqual(resp.status_code, 200)
                self.assertIn("image/png", resp.content_type)


if __name__ == "__main__":
    unittest.main()
