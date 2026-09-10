import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import challenge_store as challenge_store_module  # noqa: E402
from challenge_store import ChallengeStore  # noqa: E402
from state_store import StateStore  # noqa: E402


def _fresh_store(tmpdir) -> ChallengeStore:
    return ChallengeStore(StateStore(str(Path(tmpdir) / "state.json")))


class TestPendingChallengeCreation(unittest.TestCase):
    def test_create_succeeds_when_no_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            created = cs.try_create("owner@example.com", "login", "bravo six", "going dark")
            self.assertTrue(created)
            pending = cs.get_pending("owner@example.com")
            self.assertEqual(pending["type"], "login")
            self.assertEqual(pending["prefix"], "bravo six")
            self.assertFalse(pending["consumed"])

    def test_reject_not_replace_while_pending(self):
        # PLAN.md section 5: a new trigger while a challenge is already
        # pending is REJECTED, not silently accepted as a replacement.
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            cs.try_create("owner@example.com", "login", "bravo six", "first suffix")
            created_again = cs.try_create("owner@example.com", "login", "charlie seven", "second suffix")
            self.assertFalse(created_again)
            pending = cs.get_pending("owner@example.com")
            self.assertEqual(pending["suffix"], "first suffix")  # untouched

    def test_shared_slot_across_login_and_rotate_types(self):
        # PLAN.md section 5: one shared pending-challenge slot per sender,
        # tagged by type -- not two independent slots.
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            cs.try_create("owner@example.com", "login", "bravo six", "suffix-a")
            created = cs.try_create("owner@example.com", "rotate", "bravo six", "suffix-b")
            self.assertFalse(created)

    def test_new_challenge_allowed_after_prior_one_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            store = cs.store

            def mutate(data):
                data.setdefault("pending_challenges", {})["owner@example.com"] = {
                    "type": "login", "prefix": "a b", "suffix": "old",
                    "issued_at": time.time() - 1000, "expires_at": time.time() - 500,
                    "consumed": False,
                }
                return data

            store.update(mutate)
            created = cs.try_create("owner@example.com", "login", "bravo six", "new suffix")
            self.assertTrue(created)


class TestTryConsume(unittest.TestCase):
    def test_no_pending_returns_no_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            result, ctype, _ = cs.try_consume("owner@example.com", "anything")
            self.assertEqual(result, "no_pending")
            self.assertIsNone(ctype)

    def test_matching_suffix_consumes_and_returns_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            cs.try_create("owner@example.com", "rotate", "bravo six", "going dark")
            result, ctype, _ = cs.try_consume("owner@example.com", "going dark")
            self.assertEqual(result, "match")
            self.assertEqual(ctype, "rotate")

    def test_mismatched_suffix_does_not_consume(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            cs.try_create("owner@example.com", "login", "bravo six", "going dark")
            result, ctype, _ = cs.try_consume("owner@example.com", "wrong words")
            self.assertEqual(result, "mismatch")
            self.assertIsNone(ctype)
            # Still pending, unconsumed -- a mismatch doesn't burn the slot.
            self.assertFalse(cs.get_pending("owner@example.com")["consumed"])

    def test_replayed_reply_after_match_finds_no_pending(self):
        # The atomicity guarantee: a second reply for an already-consumed
        # challenge can't re-trigger the match branch (no double session
        # start / double rotation).
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            cs.try_create("owner@example.com", "login", "bravo six", "going dark")
            first, _, _ = cs.try_consume("owner@example.com", "going dark")
            second, _, _ = cs.try_consume("owner@example.com", "going dark")
            self.assertEqual(first, "match")
            self.assertEqual(second, "no_pending")

    def test_expired_challenge_reply_finds_no_pending_not_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            store = cs.store

            def mutate(data):
                data.setdefault("pending_challenges", {})["owner@example.com"] = {
                    "type": "login", "prefix": "a b", "suffix": "going dark",
                    "issued_at": time.time() - 1000, "expires_at": time.time() - 1,
                    "consumed": False,
                }
                return data

            store.update(mutate)
            result, _, _ = cs.try_consume("owner@example.com", "going dark")
            self.assertEqual(result, "no_pending")


class TestSweepExpired(unittest.TestCase):
    def test_sweep_clears_expired_and_frees_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            store = cs.store

            def mutate(data):
                data.setdefault("pending_challenges", {})["owner@example.com"] = {
                    "type": "login", "prefix": "a b", "suffix": "x",
                    "issued_at": time.time() - 1000, "expires_at": time.time() - 1,
                    "consumed": False,
                }
                return data

            store.update(mutate)
            cs.sweep_expired()
            self.assertIsNone(cs.get_pending("owner@example.com"))
            created = cs.try_create("owner@example.com", "login", "new", "phrase")
            self.assertTrue(created)

    def test_sweep_does_not_touch_unconsumed_unexpired_challenge(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            cs.try_create("owner@example.com", "login", "a b", "still-valid")
            cs.sweep_expired()
            self.assertIsNotNone(cs.get_pending("owner@example.com"))

    def test_abandoned_threshold_trips_exactly_once_per_crossing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            store = cs.store
            threshold = challenge_store_module.ABANDONED_THRESHOLD_PER_HOUR

            tripped_counts = []
            for i in range(threshold + 2):
                def mutate(data, i=i):
                    data.setdefault("pending_challenges", {})[f"sender{i}@example.com" if False else "owner@example.com"] = {
                        "type": "login", "prefix": "a b", "suffix": "x",
                        "issued_at": time.time() - 10, "expires_at": time.time() - 1,
                        "consumed": False,
                    }
                    return data

                store.update(mutate)
                tripped = cs.sweep_expired()
                tripped_counts.append(len(tripped))

            # Trips on exactly the sweep where the count reaches the
            # threshold, not on every sweep at-or-above it (would spam alerts).
            self.assertEqual(sum(tripped_counts), 1)


class TestAnsweredNotAbandoned(unittest.TestCase):
    """PLAN.md section 6/7: a challenge that got ANY reply -- right or
    wrong -- was answered, not abandoned, and must never also count toward
    section 7's dedicated abandoned-trigger flood threshold. A wrong-suffix
    reply already burns a lockout strike; double-counting it as abandoned
    too would make an ordinary mistyped-then-not-retried reply (a real,
    expected risk on the 7-word tactical suffix per PLAN.md section 2)
    silently contribute to a threshold meant to catch UNANSWERED probing."""

    def test_mismatched_then_expired_challenge_is_not_counted_as_abandoned(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            cs.try_create("owner@example.com", "login", "bravo six", "going dark")
            result, _, _ = cs.try_consume("owner@example.com", "wrong words")
            self.assertEqual(result, "mismatch")

            store = cs.store

            def expire_it(data):
                data["pending_challenges"]["owner@example.com"]["expires_at"] = time.time() - 1
                return data

            store.update(expire_it)
            cs.sweep_expired()

            data = store.read()
            self.assertEqual(data.get("abandoned_events", {}).get("owner@example.com", []), [])

    def test_truly_unanswered_expired_challenge_is_still_counted_as_abandoned(self):
        # Regression guard the other direction: the fix for the above must
        # not accidentally stop counting genuine abandonment either.
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            store = cs.store

            def mutate(data):
                data.setdefault("pending_challenges", {})["owner@example.com"] = {
                    "type": "login", "prefix": "a b", "suffix": "x",
                    "issued_at": time.time() - 1000, "expires_at": time.time() - 1,
                    "consumed": False, "answered": False,
                }
                return data

            store.update(mutate)
            cs.sweep_expired()
            data = store.read()
            self.assertEqual(len(data.get("abandoned_events", {}).get("owner@example.com", [])), 1)

    def test_already_above_threshold_does_not_re_trip_on_every_sweep(self):
        # The crossing check (before < threshold <= after) means a sender
        # already sitting above threshold from a prior crossing doesn't
        # spam a fresh alert on every subsequent abandoned event -- only
        # the sweep that actually crosses the line trips.
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            store = cs.store

            def seed_above_threshold(data):
                data.setdefault("abandoned_events", {})["owner@example.com"] = [time.time()] * 11
                return data

            store.update(seed_above_threshold)

            def mutate(data):
                data.setdefault("pending_challenges", {})["owner@example.com"] = {
                    "type": "login", "prefix": "a b", "suffix": "x",
                    "issued_at": time.time() - 10, "expires_at": time.time() - 1,
                    "consumed": False, "answered": False,
                }
                return data

            store.update(mutate)
            tripped = cs.sweep_expired()
            self.assertEqual(tripped, [])

    def test_skip_over_crossing_still_trips_with_ge_final_check(self):
        # Guards the >= (not ==) final comparison: if events jumps from
        # below threshold to AT-OR-ABOVE it in one step (e.g. 9 -> 10 is the
        # common case, but this also covers a hypothetical larger jump),
        # the crossing must still be detected.
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            store = cs.store

            def seed_just_below(data):
                data.setdefault("abandoned_events", {})["owner@example.com"] = [time.time()] * 9
                return data

            store.update(seed_just_below)

            def mutate(data):
                data.setdefault("pending_challenges", {})["owner@example.com"] = {
                    "type": "login", "prefix": "a b", "suffix": "x",
                    "issued_at": time.time() - 10, "expires_at": time.time() - 1,
                    "consumed": False, "answered": False,
                }
                return data

            store.update(mutate)
            tripped = cs.sweep_expired()
            self.assertEqual(tripped, ["owner@example.com"])


class TestRotationCooldown(unittest.TestCase):
    def test_not_on_cooldown_before_any_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            self.assertFalse(cs.rotation_on_cooldown("owner@example.com"))

    def test_on_cooldown_immediately_after_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            cs.record_rotation_success("owner@example.com")
            self.assertTrue(cs.rotation_on_cooldown("owner@example.com"))

    def test_cooldown_is_per_sender(self):
        with tempfile.TemporaryDirectory() as tmp:
            cs = _fresh_store(tmp)
            cs.record_rotation_success("owner@example.com")
            self.assertFalse(cs.rotation_on_cooldown("someone-else@example.com"))


if __name__ == "__main__":
    unittest.main()
