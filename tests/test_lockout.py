import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from lockout import LockoutTracker
from state_store import StateStore


class TestLockout(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.store = StateStore(str(Path(self.tmpdir.name) / "state.json"))
        self.lockout = LockoutTracker(self.store, max_failed_attempts=3, lockout_minutes=30)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_not_locked_initially(self):
        self.assertFalse(self.lockout.is_locked("a@example.com"))

    def test_locks_after_threshold(self):
        self.assertFalse(self.lockout.record_failure("a@example.com"))
        self.assertFalse(self.lockout.record_failure("a@example.com"))
        self.assertTrue(self.lockout.record_failure("a@example.com"))
        self.assertTrue(self.lockout.is_locked("a@example.com"))

    def test_success_clears_failures(self):
        self.lockout.record_failure("a@example.com")
        self.lockout.record_failure("a@example.com")
        self.lockout.record_success("a@example.com")
        self.assertFalse(self.lockout.record_failure("a@example.com"))  # back to 1, not 3

    def test_state_persists_across_new_tracker_instance(self):
        self.lockout.record_failure("a@example.com")
        self.lockout.record_failure("a@example.com")
        self.lockout.record_failure("a@example.com")
        self.assertTrue(self.lockout.is_locked("a@example.com"))

        # Simulate a crash/restart: new tracker instance, same store.
        restarted = LockoutTracker(self.store, max_failed_attempts=3, lockout_minutes=30)
        self.assertTrue(restarted.is_locked("a@example.com"))

    def test_lockout_is_per_sender(self):
        for _ in range(3):
            self.lockout.record_failure("attacker@example.com")
        self.assertTrue(self.lockout.is_locked("attacker@example.com"))
        self.assertFalse(self.lockout.is_locked("owner@example.com"))


if __name__ == "__main__":
    unittest.main()
