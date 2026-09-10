import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from heartbeat import Heartbeat  # noqa: E402


class TestPhraseRotationOverdue(unittest.TestCase):
    def test_fresh_phrase_file_is_not_overdue(self):
        with tempfile.TemporaryDirectory() as tmp:
            phrase_path = Path(tmp) / "phrase.txt"
            phrase_path.write_text("bravo six\ngoing dark")
            hb = Heartbeat(vnc_host="127.0.0.1", vnc_port=5900, phrase_path=str(phrase_path))
            self.assertFalse(hb.phrase_rotation_overdue())

    def test_stale_phrase_file_is_overdue(self):
        with tempfile.TemporaryDirectory() as tmp:
            phrase_path = Path(tmp) / "phrase.txt"
            phrase_path.write_text("bravo six\ngoing dark")
            old_time = time.time() - (31 * 3600)
            import os
            os.utime(phrase_path, (old_time, old_time))
            hb = Heartbeat(vnc_host="127.0.0.1", vnc_port=5900, phrase_path=str(phrase_path))
            self.assertTrue(hb.phrase_rotation_overdue())

    def test_missing_phrase_file_reports_overdue_rather_than_raising(self):
        hb = Heartbeat(vnc_host="127.0.0.1", vnc_port=5900, phrase_path="/nonexistent/phrase.txt")
        self.assertTrue(hb.phrase_rotation_overdue())

    def test_report_cycle_reports_degraded_state_when_rotation_overdue(self):
        with tempfile.TemporaryDirectory() as tmp:
            phrase_path = Path(tmp) / "phrase.txt"
            phrase_path.write_text("bravo six\ngoing dark")
            old_time = time.time() - (31 * 3600)
            import os
            os.utime(phrase_path, (old_time, old_time))
            hb = Heartbeat(vnc_host="127.0.0.1", vnc_port=5900, phrase_path=str(phrase_path))
            with patch.object(hb, "vnc_reachable", return_value=True):
                state = hb.report_cycle(watcher_ok=True)
            self.assertIn("rotation overdue", state)

    def test_healthy_when_everything_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            phrase_path = Path(tmp) / "phrase.txt"
            phrase_path.write_text("bravo six\ngoing dark")
            hb = Heartbeat(vnc_host="127.0.0.1", vnc_port=5900, phrase_path=str(phrase_path))
            with patch.object(hb, "vnc_reachable", return_value=True):
                state = hb.report_cycle(watcher_ok=True)
            self.assertEqual(state, "healthy")


class TestSecurityLevel1TooLong(unittest.TestCase):
    def _fresh_phrase_path(self, tmp) -> str:
        phrase_path = Path(tmp) / "phrase.txt"
        phrase_path.write_text("bravo six\ngoing dark")
        return str(phrase_path)

    def test_no_security_level_store_never_flags_this_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            hb = Heartbeat(vnc_host="127.0.0.1", vnc_port=5900, phrase_path=self._fresh_phrase_path(tmp))
            self.assertFalse(hb.security_level_1_too_long())

    def test_level_2_never_flags_regardless_of_since_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = MagicMock()
            sls.get_level.return_value = 2
            sls.get_since.return_value = time.time() - (100 * 3600)
            hb = Heartbeat(
                vnc_host="127.0.0.1", vnc_port=5900, phrase_path=self._fresh_phrase_path(tmp),
                security_level_store=sls, l1_max_continuous_hours=24,
            )
            self.assertFalse(hb.security_level_1_too_long())

    def test_level_1_recently_entered_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = MagicMock()
            sls.get_level.return_value = 1
            sls.get_since.return_value = time.time() - 60  # 1 minute ago
            hb = Heartbeat(
                vnc_host="127.0.0.1", vnc_port=5900, phrase_path=self._fresh_phrase_path(tmp),
                security_level_store=sls, l1_max_continuous_hours=24,
            )
            self.assertFalse(hb.security_level_1_too_long())

    def test_level_1_active_past_threshold_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = MagicMock()
            sls.get_level.return_value = 1
            sls.get_since.return_value = time.time() - (25 * 3600)
            hb = Heartbeat(
                vnc_host="127.0.0.1", vnc_port=5900, phrase_path=self._fresh_phrase_path(tmp),
                security_level_store=sls, l1_max_continuous_hours=24,
            )
            self.assertTrue(hb.security_level_1_too_long())

    def test_report_cycle_reports_degraded_state_for_stale_level_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = MagicMock()
            sls.get_level.return_value = 1
            sls.get_since.return_value = time.time() - (25 * 3600)
            hb = Heartbeat(
                vnc_host="127.0.0.1", vnc_port=5900, phrase_path=self._fresh_phrase_path(tmp),
                security_level_store=sls, l1_max_continuous_hours=24,
            )
            with patch.object(hb, "vnc_reachable", return_value=True):
                state = hb.report_cycle(watcher_ok=True)
            self.assertIn("security level 1", state)


if __name__ == "__main__":
    unittest.main()
