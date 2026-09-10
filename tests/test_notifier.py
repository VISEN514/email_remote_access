import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from notifier import Notifier  # noqa: E402


class TestSecurityLevelAlert(unittest.TestCase):
    def test_entering_level_1_email_mentions_allow_list_dropped(self):
        gmail = MagicMock()
        notifier = Notifier(gmail, alert_to="owner@example.com")
        notifier.send_security_level_alert(1)
        gmail.send.assert_called_once()
        _, kwargs = gmail.send.call_args
        self.assertEqual(kwargs["to"], "owner@example.com")
        self.assertIn("allow-list", kwargs["body"].lower())

    def test_level_2_email_mentions_default(self):
        gmail = MagicMock()
        notifier = Notifier(gmail, alert_to="owner@example.com")
        notifier.send_security_level_alert(2)
        gmail.send.assert_called_once()
        _, kwargs = gmail.send.call_args
        self.assertIn("2", kwargs["body"])


if __name__ == "__main__":
    unittest.main()
