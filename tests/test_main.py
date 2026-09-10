import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import importlib

import main as main_module  # noqa: E402
from challenge_store import ChallengeStore  # noqa: E402
from state_store import StateStore  # noqa: E402


def _config_stub():
    config = MagicMock()
    config.access = {"lockout_minutes": 30, "default_phrase_style": "diceware"}
    config.session = {"absolute_timeout_minutes": 60}
    return config


class TestOnValidRequest(unittest.TestCase):
    def setUp(self):
        importlib.reload(main_module)

    def test_challenge_prefix_sends_prefix_email_only(self):
        broker = MagicMock()
        notifier = MagicMock()
        on_valid_request = main_module.build_on_valid_request(broker, notifier, _config_stub())

        on_valid_request(sender="owner@example.com", valid=None, just_locked=False, challenge_prefix="bravo six")

        notifier.send_challenge_prefix.assert_called_once_with("bravo six")
        broker.start_session.assert_not_called()

    def test_just_locked_sends_lockout_alert_only(self):
        broker = MagicMock()
        notifier = MagicMock()
        on_valid_request = main_module.build_on_valid_request(broker, notifier, _config_stub())

        on_valid_request(sender="owner@example.com", valid=False, just_locked=True, challenge_prefix=None)

        notifier.send_lockout_alert.assert_called_once()
        notifier.send_wrong_suffix_alert.assert_not_called()
        broker.start_session.assert_not_called()

    def test_wrong_suffix_not_locked_sends_wrong_suffix_alert(self):
        broker = MagicMock()
        notifier = MagicMock()
        on_valid_request = main_module.build_on_valid_request(broker, notifier, _config_stub())

        on_valid_request(sender="owner@example.com", valid=False, just_locked=False, challenge_prefix=None)

        notifier.send_wrong_suffix_alert.assert_called_once()
        broker.start_session.assert_not_called()

    def test_valid_match_starts_session_without_rotating_phrase(self):
        broker = MagicMock()
        broker.start_session.return_value = "https://example.trycloudflare.com/connect/nonce"
        notifier = MagicMock()
        notifier.send_session_link.return_value = True
        on_valid_request = main_module.build_on_valid_request(broker, notifier, _config_stub())

        on_valid_request(sender="owner@example.com", valid=True, just_locked=False, challenge_prefix=None)

        broker.start_session.assert_called_once()
        notifier.send_session_link.assert_called_once_with(
            "https://example.trycloudflare.com/connect/nonce", 60
        )

    def test_session_start_failure_notifies_and_does_not_raise(self):
        broker = MagicMock()
        broker.start_session.side_effect = RuntimeError("tunnel failed")
        notifier = MagicMock()
        on_valid_request = main_module.build_on_valid_request(broker, notifier, _config_stub())

        on_valid_request(sender="owner@example.com", valid=True, just_locked=False, challenge_prefix=None)

        notifier.send_session_start_failed.assert_called_once()
        notifier.send_session_link.assert_not_called()


class TestOnRotation(unittest.TestCase):
    def test_cooldown_active_skips_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            challenges = ChallengeStore(StateStore(str(Path(tmp) / "state.json")))
            challenges.record_rotation_success("owner@example.com")

            phrase_manager = MagicMock()
            notifier = MagicMock()
            on_rotation = main_module.build_on_rotation(phrase_manager, challenges, notifier, _config_stub())

            on_rotation(sender="owner@example.com", style="diceware")

            phrase_manager.remote_rotate.assert_not_called()
            notifier.send_rotation_on_cooldown.assert_called_once()

    def test_no_cooldown_rotates_and_emails_new_phrase(self):
        with tempfile.TemporaryDirectory() as tmp:
            challenges = ChallengeStore(StateStore(str(Path(tmp) / "state.json")))

            phrase_manager = MagicMock()
            new_phrase = MagicMock()
            new_phrase.full = "delta four correct horse battery staple"
            phrase_manager.remote_rotate.return_value = new_phrase
            notifier = MagicMock()
            notifier.send_rotated_phrase.return_value = True

            on_rotation = main_module.build_on_rotation(phrase_manager, challenges, notifier, _config_stub())
            on_rotation(sender="owner@example.com", style="diceware")

            phrase_manager.remote_rotate.assert_called_once_with("diceware")
            notifier.send_rotated_phrase.assert_called_once_with("delta four correct horse battery staple")
            self.assertTrue(challenges.rotation_on_cooldown("owner@example.com"))

    def test_rotation_failure_does_not_record_cooldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            challenges = ChallengeStore(StateStore(str(Path(tmp) / "state.json")))

            phrase_manager = MagicMock()
            phrase_manager.remote_rotate.side_effect = OSError("disk full")
            notifier = MagicMock()

            on_rotation = main_module.build_on_rotation(phrase_manager, challenges, notifier, _config_stub())
            on_rotation(sender="owner@example.com", style="diceware")

            notifier.send_phrase_rotation_failed.assert_called_once()
            self.assertFalse(challenges.rotation_on_cooldown("owner@example.com"))


class TestOnSessionEnd(unittest.TestCase):
    def test_clean_teardown_sends_clean_confirmation(self):
        notifier = MagicMock()
        on_session_end = main_module.build_on_session_end(notifier)
        on_session_end(clean=True)
        notifier.send_logout_confirmation.assert_called_once_with(clean=True)

    def test_partial_teardown_sends_partial_confirmation(self):
        notifier = MagicMock()
        on_session_end = main_module.build_on_session_end(notifier)
        on_session_end(clean=False)
        notifier.send_logout_confirmation.assert_called_once_with(clean=False)


if __name__ == "__main__":
    unittest.main()
