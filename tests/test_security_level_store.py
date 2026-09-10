import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from security_level_store import DEFAULT_LEVEL, SecurityLevelStore  # noqa: E402
from state_store import StateStore  # noqa: E402


def _fresh_sls(tmpdir, allowed_senders=("owner@allowed.example",), max_new_senders_per_hour=15) -> SecurityLevelStore:
    store = StateStore(str(Path(tmpdir) / "state.json"))
    return SecurityLevelStore(store, allowed_senders=allowed_senders, max_new_senders_per_hour=max_new_senders_per_hour)


class TestGetLevelDefault(unittest.TestCase):
    def test_default_is_hardcoded_safe_level_2_when_never_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            self.assertEqual(sls.get_level(), 2)
            self.assertEqual(DEFAULT_LEVEL, 2)

    def test_get_since_is_zero_when_never_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            self.assertEqual(sls.get_since(), 0)


class TestConfigSeededDefault(unittest.TestCase):
    def test_default_level_from_config_is_used_when_never_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(str(Path(tmp) / "state.json"))
            sls = SecurityLevelStore(store, allowed_senders=[], default_level=1)
            self.assertEqual(sls.get_level(), 1)

    def test_invalid_default_level_falls_back_to_hardcoded_safe_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(str(Path(tmp) / "state.json"))
            sls = SecurityLevelStore(store, allowed_senders=[], default_level=99)
            self.assertEqual(sls.get_level(), DEFAULT_LEVEL)

    def test_config_seeded_default_never_read_once_a_real_level_is_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(str(Path(tmp) / "state.json"))
            sls = SecurityLevelStore(store, allowed_senders=[], default_level=1)
            sls.set_level(2)
            self.assertEqual(sls.get_level(), 2)


class TestSetLevel(unittest.TestCase):
    def test_set_level_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            sls.set_level(1)
            self.assertEqual(sls.get_level(), 1)

    def test_set_level_updates_since_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            before = time.time()
            sls.set_level(1)
            after = time.time()
            since = sls.get_since()
            self.assertGreaterEqual(since, before)
            self.assertLessEqual(since, after)

    def test_idempotent_reset_of_already_active_level_does_not_reset_since(self):
        # Regression guard: a redundant click on an already-selected popup
        # segment must not reset the staleness clock heartbeat's
        # L1-too-long check depends on -- otherwise a single accidental
        # re-click could suppress that detection indefinitely.
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            sls.set_level(1)
            original_since = sls.get_since()
            time.sleep(0.05)
            sls.set_level(1)  # idempotent -- level doesn't change
            self.assertEqual(sls.get_since(), original_since)

    def test_genuine_transition_does_update_since(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            sls.set_level(1)
            first_since = sls.get_since()
            time.sleep(0.05)
            sls.set_level(2)  # genuine change
            self.assertGreater(sls.get_since(), first_since)

    def test_alert_fires_on_genuine_transition_into_level_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)  # starts at default level 2
            notifier = MagicMock()
            sls.set_level(1, notifier=notifier)
            notifier.send_security_level_alert.assert_called_once_with(1)

    def test_alert_does_not_fire_on_idempotent_reset_of_already_active_level_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            notifier = MagicMock()
            sls.set_level(1, notifier=notifier)
            notifier.reset_mock()
            sls.set_level(1, notifier=notifier)  # already 1 -- not a transition
            notifier.send_security_level_alert.assert_not_called()

    def test_alert_does_not_fire_on_transition_out_of_level_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            notifier = MagicMock()
            sls.set_level(1, notifier=notifier)
            notifier.reset_mock()
            sls.set_level(2, notifier=notifier)
            notifier.send_security_level_alert.assert_not_called()

    def test_alert_fires_again_on_repeated_l2_to_l1_toggling(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            notifier = MagicMock()
            sls.set_level(1, notifier=notifier)
            sls.set_level(2, notifier=notifier)
            sls.set_level(1, notifier=notifier)
            self.assertEqual(notifier.send_security_level_alert.call_count, 2)

    def test_no_notifier_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)
            sls.set_level(1, notifier=None)  # must not raise
            self.assertEqual(sls.get_level(), 1)


class TestL1FloodCap(unittest.TestCase):
    def test_record_is_noop_at_level_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp)  # default level 2
            for i in range(20):
                sls.record_new_sender_if_l1(f"stranger{i}@example.com")
            self.assertFalse(sls.l1_new_sender_cap_exceeded())

    def test_record_is_noop_for_allow_listed_sender_even_at_level_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp, max_new_senders_per_hour=2)
            sls.set_level(1)
            for _ in range(10):
                sls.record_new_sender_if_l1("owner@allowed.example")
            self.assertFalse(sls.l1_new_sender_cap_exceeded())

    def test_same_sender_triggering_many_times_counts_once(self):
        # Proves the dict-by-sender structure distinguishes "one sender
        # repeatedly" from "many distinct senders" -- the exact property
        # round 3's bare-timestamp-list attempt could NOT provide.
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp, max_new_senders_per_hour=2)
            sls.set_level(1)
            for _ in range(100):
                sls.record_new_sender_if_l1("stranger@example.com")
            self.assertFalse(sls.l1_new_sender_cap_exceeded())

    def test_many_distinct_senders_trips_the_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp, max_new_senders_per_hour=5)
            sls.set_level(1)
            for i in range(10):
                sls.record_new_sender_if_l1(f"stranger{i}@example.com")
            self.assertTrue(sls.l1_new_sender_cap_exceeded())

    def test_pacing_slowly_across_many_calls_still_trips_rolling_cap(self):
        # Guards against the round-2 per-cycle bypass: spreading distinct
        # senders out (not bursting) must still trip a ROLLING window cap.
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp, max_new_senders_per_hour=5)
            sls.set_level(1)
            for i in range(10):
                sls.record_new_sender_if_l1(f"paced{i}@example.com")
                # no cap check in between -- simulates spread-out arrival,
                # all still within the same rolling hour
            self.assertTrue(sls.l1_new_sender_cap_exceeded())

    def test_entries_older_than_an_hour_are_pruned_and_dont_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            sls = _fresh_sls(tmp, max_new_senders_per_hour=2)
            sls.set_level(1)
            old_time = time.time() - 7200  # 2 hours ago

            def mutate(data):
                data.setdefault("new_sender_last_seen", {})["ancient@example.com"] = old_time
                data["new_sender_last_seen"]["ancient2@example.com"] = old_time
                data["new_sender_last_seen"]["ancient3@example.com"] = old_time
                return data

            sls.store.update(mutate)
            self.assertFalse(sls.l1_new_sender_cap_exceeded())


if __name__ == "__main__":
    unittest.main()
