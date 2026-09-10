import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from challenge_store import ChallengeStore  # noqa: E402
from mail_watcher import MailWatcher, _extract_sender  # noqa: E402
from phrase_manager import Passphrase  # noqa: E402
from security_level_store import SecurityLevelStore  # noqa: E402
from state_store import StateStore  # noqa: E402


def _fresh_state_store(tmpdir) -> StateStore:
    return StateStore(str(Path(tmpdir) / "state.json"))


def _headers_for(sender: str) -> list[dict]:
    return [
        {"name": "From", "value": sender},
        {"name": "Authentication-Results", "value": "mx.google.com; spf=pass dkim=pass dmarc=pass"},
        {"name": "Received", "value": "by mx.google.com with SMTP id x"},
    ]


def _make_watcher(gmail, store, phrase=None, lockout=None, on_valid_request=None, on_rotation=None,
                  on_abandoned_flood=None, allowed_senders=("owner@allowed.example",),
                  security_level_store=None):
    phrase_manager = MagicMock()
    phrase_manager.current_phrase.return_value = phrase or Passphrase(prefix="bravo six", suffix="going dark")
    lockout = lockout or MagicMock(is_locked=MagicMock(return_value=False))
    sls = security_level_store or SecurityLevelStore(store, allowed_senders=list(allowed_senders))
    return MailWatcher(
        gmail=gmail,
        access_config={"allowed_senders": list(allowed_senders)},
        flood_config={"threshold_per_cycle": 100},
        trusted_authserv_id="mx.google.com",
        lockout=lockout,
        phrase_manager=phrase_manager,
        challenges=ChallengeStore(store),
        security_level_store=sls,
        on_valid_request=on_valid_request or MagicMock(),
        on_rotation=on_rotation or MagicMock(),
        on_abandoned_flood=on_abandoned_flood or MagicMock(),
        handled_ids_store=store,
    )


class TestExtractSender(unittest.TestCase):
    def test_plain_address(self):
        headers = [{"name": "From", "value": "av.oct15@gmail.com"}]
        self.assertEqual(_extract_sender(headers), "av.oct15@gmail.com")

    def test_display_name_with_real_address(self):
        headers = [{"name": "From", "value": "Owner Name <av.oct15@gmail.com>"}]
        self.assertEqual(_extract_sender(headers), "av.oct15@gmail.com")

    def test_display_name_spoofing_decoy_is_not_extracted(self):
        headers = [{"name": "From", "value": '"av.oct15@gmail.com" <attacker@evil-domain.com>'}]
        self.assertEqual(_extract_sender(headers), "attacker@evil-domain.com")
        self.assertNotEqual(_extract_sender(headers), "av.oct15@gmail.com")

    def test_missing_from_header(self):
        self.assertIsNone(_extract_sender([]))


class TestTriggerIssuesChallenge(unittest.TestCase):
    def test_recognized_login_trigger_creates_challenge_and_sends_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "Tap me in"

            on_valid_request = MagicMock()
            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store, on_valid_request=on_valid_request)

            ok = watcher.poll_once()
            self.assertTrue(ok)
            on_valid_request.assert_called_once_with(
                sender="owner@allowed.example", valid=None, just_locked=False, challenge_prefix="bravo six"
            )
            gmail.mark_read.assert_called_once_with("msg1")
            gmail.batch_archive.assert_called_once_with([], trash_instead=False)

    def test_recognized_rotate_trigger_creates_rotate_typed_challenge(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "rotate phrase"

            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store)
            watcher.poll_once()

            pending = watcher.challenges.get_pending("owner@allowed.example")
            self.assertEqual(pending["type"], "rotate")

    def test_trigger_while_pending_is_rejected_not_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "tap me in"

            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store)
            watcher.challenges.try_create("owner@allowed.example", "login", "old pre", "old-suffix")

            watcher.poll_once()
            pending = watcher.challenges.get_pending("owner@allowed.example")
            self.assertEqual(pending["suffix"], "old-suffix")  # untouched
            gmail.batch_archive.assert_called_once_with(["msg1"], trash_instead=False)


class TestReplyToChallenge(unittest.TestCase):
    def test_matching_suffix_fires_on_valid_request_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "going dark"

            on_valid_request = MagicMock()
            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store, on_valid_request=on_valid_request)
            watcher.challenges.try_create("owner@allowed.example", "login", "bravo six", "going dark")

            watcher.poll_once()
            on_valid_request.assert_called_once_with(
                sender="owner@allowed.example", valid=True, just_locked=False, challenge_prefix=None
            )

    def test_mismatched_suffix_fires_on_valid_request_false_and_lockout_strike(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "wrong words"

            lockout = MagicMock()
            lockout.is_locked.return_value = False
            lockout.record_failure.return_value = False

            on_valid_request = MagicMock()
            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store, lockout=lockout, on_valid_request=on_valid_request)
            watcher.challenges.try_create("owner@allowed.example", "login", "bravo six", "going dark")

            watcher.poll_once()
            lockout.record_failure.assert_called_once_with("owner@allowed.example")
            on_valid_request.assert_called_once_with(
                sender="owner@allowed.example", valid=False, just_locked=False, challenge_prefix=None
            )

    def test_matching_suffix_for_rotate_challenge_fires_on_rotation_not_on_valid_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "going dark"

            on_valid_request = MagicMock()
            on_rotation = MagicMock()
            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store, on_valid_request=on_valid_request, on_rotation=on_rotation)
            watcher.challenges.try_create("owner@allowed.example", "rotate", "bravo six", "going dark")

            watcher.poll_once()
            on_rotation.assert_called_once()
            on_valid_request.assert_not_called()

    def test_reply_with_no_pending_challenge_is_archived_without_lockout_strike(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "some random text"

            lockout = MagicMock()
            lockout.is_locked.return_value = False
            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store, lockout=lockout)

            watcher.poll_once()
            lockout.record_failure.assert_not_called()
            gmail.batch_archive.assert_called_once_with(["msg1"], trash_instead=False)


class TestChallengePartsLockedAtIssuance(unittest.TestCase):
    """PLAN.md section 5: 'Persisting the specific parts used at issuance
    (not re-deriving from "whatever the current phrase is" at response
    time) means a phrase rotation landing mid-challenge can't invalidate a
    legitimate login.' PLAN.md build step 8 explicitly calls this out as
    required coverage; this test actually rotates the phrase between issuing
    a challenge and replying to it."""

    def test_reply_still_matches_old_suffix_after_phrase_rotates_mid_challenge(self):
        with tempfile.TemporaryDirectory() as tmp:
            phrase_path = Path(tmp) / "phrase.txt"
            next_path = Path(tmp) / "phrase.next"
            from phrase_manager import PhraseManager as RealPhraseManager

            real_pm = RealPhraseManager(str(phrase_path), str(next_path))
            real_pm.set_custom_phrase("bravo six going dark echo delta hotel signal breach", "tactical")

            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg_trigger"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "tap me in"

            store = _fresh_state_store(tmp)
            watcher = MailWatcher(
                gmail=gmail,
                access_config={"allowed_senders": ["owner@allowed.example"]},
                flood_config={"threshold_per_cycle": 100},
                trusted_authserv_id="mx.google.com",
                lockout=MagicMock(is_locked=MagicMock(return_value=False)),
                phrase_manager=real_pm,
                challenges=ChallengeStore(store),
                security_level_store=SecurityLevelStore(store, allowed_senders=["owner@allowed.example"]),
                on_valid_request=MagicMock(),
                on_rotation=MagicMock(),
                on_abandoned_flood=MagicMock(),
                handled_ids_store=store,
            )
            watcher.poll_once()  # issues the challenge against today's phrase

            # Phrase rotates mid-challenge (e.g. the 6am popup fires while a
            # login is in flight).
            real_pm.physical_reset("diceware")

            on_valid_request = MagicMock()
            watcher.on_valid_request = on_valid_request
            gmail.list_unread_ids.return_value = ["msg_reply"]
            gmail.get_body_text.return_value = "going dark echo delta hotel signal breach"

            watcher.poll_once()
            on_valid_request.assert_called_once_with(
                sender="owner@allowed.example", valid=True, just_locked=False, challenge_prefix=None
            )


class TestAbandonedChallengeSweep(unittest.TestCase):
    def test_expired_pending_is_swept_before_processing_new_messages(self):
        with tempfile.TemporaryDirectory() as tmp:
            import time as _time

            gmail = MagicMock()
            gmail.list_unread_ids.return_value = []

            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store)

            def mutate(data):
                data.setdefault("pending_challenges", {})["owner@allowed.example"] = {
                    "type": "login", "prefix": "a b", "suffix": "x",
                    "issued_at": _time.time() - 1000, "expires_at": _time.time() - 1,
                    "consumed": False,
                }
                return data

            store.update(mutate)
            watcher.poll_once()
            self.assertIsNone(watcher.challenges.get_pending("owner@allowed.example"))


class TestSecurityLevelGate(unittest.TestCase):
    """PLAN.md 'Selectable security levels': Level 2 keeps today's
    allow-list gate exactly as-is; Level 1 skips it for authenticated
    senders (authentication itself is never skipped at either level)."""

    def test_level_2_default_still_rejects_non_allow_listed_sender(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("stranger@example.com")
            gmail.get_body_text.return_value = "tap me in"

            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store)  # default level 2

            watcher.poll_once()
            gmail.batch_archive.assert_called_once_with(["msg1"], trash_instead=False)
            self.assertIsNone(watcher.challenges.get_pending("stranger@example.com"))

    def test_level_1_accepts_non_allow_listed_authenticated_sender(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("stranger@example.com")
            gmail.get_body_text.return_value = "tap me in"

            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store)
            watcher.security_level_store.set_level(1)

            on_valid_request = MagicMock()
            watcher.on_valid_request = on_valid_request

            watcher.poll_once()
            on_valid_request.assert_called_once_with(
                sender="stranger@example.com", valid=None, just_locked=False, challenge_prefix="bravo six"
            )
            gmail.batch_archive.assert_called_once_with([], trash_instead=False)

    def test_authentication_is_never_skipped_at_level_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            # Missing Authentication-Results / Received -- fails auth
            # regardless of allow-list or security level.
            gmail.get_headers.return_value = [{"name": "From", "value": "stranger@example.com"}]
            gmail.get_body_text.return_value = "tap me in"

            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store)
            watcher.security_level_store.set_level(1)

            watcher.poll_once()
            gmail.batch_archive.assert_called_once_with(["msg1"], trash_instead=False)

    def test_security_level_is_read_once_per_cycle_not_per_message(self):
        # A level flip mid-cycle (simulated here by making the store report
        # a different value starting on the SECOND read) must NOT split
        # policy within the same poll_once() call -- the allow-list-skip
        # decision for every message in this batch must reflect whatever
        # level was resolved at the very top of the cycle, even though
        # something else (record_new_sender_if_l1's own internal read, per
        # PLAN.md's build step 1) legitimately reads the store again later
        # in the same cycle. Two DISTINCT non-allow-listed senders are used
        # so the second message isn't itself rejected by reject-not-replace.
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1", "msg2"]

            def get_headers(msg_id):
                sender = "stranger-one@example.com" if msg_id == "msg1" else "stranger-two@example.com"
                return _headers_for(sender)

            gmail.get_headers.side_effect = get_headers
            gmail.get_body_text.return_value = "tap me in"

            store = _fresh_state_store(tmp)
            sls = SecurityLevelStore(store, allowed_senders=["owner@allowed.example"])
            sls.set_level(1)
            watcher = _make_watcher(gmail, store, security_level_store=sls)

            real_get_level = sls.get_level
            calls = {"n": 0}

            def flipping_get_level():
                calls["n"] += 1
                # Flip the STORED level to 2 starting on the second read --
                # simulates the popup changing it mid-cycle. If mail_watcher
                # re-read get_level() for its per-message archive-skip
                # decision (instead of using the value cached once at the
                # top of poll_once), the second message would be gated as
                # Level 2 and rejected -- this test fails in that case.
                if calls["n"] >= 2:
                    real_set = SecurityLevelStore.set_level
                    real_set(sls, 2)
                return real_get_level()

            sls.get_level = flipping_get_level

            watcher.poll_once()
            # Both distinct strangers must be accepted identically -- proof
            # the archive-skip gate used one consistent, cycle-cached level
            # for the whole batch, regardless of the store's live value
            # changing partway through (via record_new_sender_if_l1's own
            # separate, legitimate internal read).
            gmail.batch_archive.assert_called_once_with([], trash_instead=False)


class TestL1NewSenderFloodCap(unittest.TestCase):
    def test_cap_exceeded_archives_new_sender_without_issuing_challenge(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("newcomer@example.com")
            gmail.get_body_text.return_value = "tap me in"

            store = _fresh_state_store(tmp)
            sls = SecurityLevelStore(store, allowed_senders=["owner@allowed.example"], max_new_senders_per_hour=1)
            sls.set_level(1)
            sls.record_new_sender_if_l1("already-one@example.com")
            sls.record_new_sender_if_l1("already-two@example.com")

            on_valid_request = MagicMock()
            watcher = _make_watcher(
                gmail, store, security_level_store=sls, on_valid_request=on_valid_request,
                allowed_senders=("owner@allowed.example",),
            )

            watcher.poll_once()
            on_valid_request.assert_not_called()
            gmail.batch_archive.assert_called_once_with(["msg1"], trash_instead=False)
            self.assertIsNone(watcher.challenges.get_pending("newcomer@example.com"))

    def test_cap_does_not_apply_at_level_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "tap me in"

            store = _fresh_state_store(tmp)
            sls = SecurityLevelStore(store, allowed_senders=["owner@allowed.example"], max_new_senders_per_hour=1)
            for i in range(5):
                sls.record_new_sender_if_l1(f"padding{i}@example.com")  # no-op at level 2

            on_valid_request = MagicMock()
            watcher = _make_watcher(gmail, store, security_level_store=sls, on_valid_request=on_valid_request)

            watcher.poll_once()
            on_valid_request.assert_called_once()

    def test_allow_listed_sender_never_archived_by_the_cap_during_active_flood(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")
            gmail.get_body_text.return_value = "tap me in"

            store = _fresh_state_store(tmp)
            sls = SecurityLevelStore(store, allowed_senders=["owner@allowed.example"], max_new_senders_per_hour=1)
            sls.set_level(1)
            # Flood well past the cap from other senders.
            for i in range(10):
                sls.record_new_sender_if_l1(f"flooder{i}@example.com")
            self.assertTrue(sls.l1_new_sender_cap_exceeded())

            on_valid_request = MagicMock()
            watcher = _make_watcher(
                gmail, store, security_level_store=sls, on_valid_request=on_valid_request,
                allowed_senders=("owner@allowed.example",),
            )

            watcher.poll_once()
            on_valid_request.assert_called_once_with(
                sender="owner@allowed.example", valid=None, just_locked=False, challenge_prefix="bravo six"
            )

    def test_sender_with_existing_pending_challenge_not_blocked_by_cap(self):
        # The cap only blocks a NEW sender's first trigger once tripped --
        # it must not cut off someone already mid-flow replying to their
        # own already-issued challenge.
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg_reply"]
            gmail.get_headers.return_value = _headers_for("midflow@example.com")
            gmail.get_body_text.return_value = "going dark"

            store = _fresh_state_store(tmp)
            sls = SecurityLevelStore(store, allowed_senders=["owner@allowed.example"], max_new_senders_per_hour=1)
            sls.set_level(1)
            for i in range(10):
                sls.record_new_sender_if_l1(f"flooder{i}@example.com")
            self.assertTrue(sls.l1_new_sender_cap_exceeded())

            on_valid_request = MagicMock()
            watcher = _make_watcher(
                gmail, store, security_level_store=sls, on_valid_request=on_valid_request,
                allowed_senders=("owner@allowed.example",),
            )
            watcher.challenges.try_create("midflow@example.com", "login", "bravo six", "going dark")

            watcher.poll_once()
            on_valid_request.assert_called_once_with(
                sender="midflow@example.com", valid=True, just_locked=False, challenge_prefix=None
            )


class TestLockedOutMessagesAreArchived(unittest.TestCase):
    def test_locked_out_sender_message_is_archived_not_left_forever(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg1"]
            gmail.get_headers.return_value = _headers_for("attacker@allowed.example")
            gmail.get_body_text.return_value = "tap me in"

            lockout = MagicMock()
            lockout.is_locked.return_value = True

            store = _fresh_state_store(tmp)
            watcher = _make_watcher(
                gmail, store, lockout=lockout, allowed_senders=("attacker@allowed.example",)
            )

            watcher.poll_once()
            gmail.batch_archive.assert_called_once()
            archived_ids = gmail.batch_archive.call_args[0][0]
            self.assertIn("msg1", archived_ids)


class TestNoSelfLockoutReplayOnMidCycleFailure(unittest.TestCase):
    def test_valid_request_is_marked_read_before_later_message_can_abort_the_cycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            gmail = MagicMock()
            gmail.list_unread_ids.return_value = ["msg_valid", "msg_that_blows_up"]
            gmail.get_headers.return_value = _headers_for("owner@allowed.example")

            def get_body_text(msg_id):
                if msg_id == "msg_valid":
                    return "tap me in"
                raise RuntimeError("transient Gmail API error fetching this message's body")

            gmail.get_body_text.side_effect = get_body_text

            store = _fresh_state_store(tmp)
            watcher = _make_watcher(gmail, store)

            ok = watcher.poll_once()
            self.assertFalse(ok)

            gmail.mark_read.assert_any_call("msg_valid")
            marked_ids = [call.args[0] for call in gmail.mark_read.call_args_list]
            self.assertNotIn("msg_that_blows_up", marked_ids)


class TestMarkReadPermanentFailureDoesNotCauseDoubleProcessing(unittest.TestCase):
    def test_dedupe_survives_a_simulated_process_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = str(Path(tmp) / "state.json")
            total_calls = 0

            for _ in range(3):
                store = StateStore(state_path)
                gmail = MagicMock()
                gmail.list_unread_ids.return_value = ["msg1"]
                gmail.get_headers.return_value = _headers_for("owner@allowed.example")
                gmail.get_body_text.return_value = "tap me in"
                gmail.mark_read.side_effect = RuntimeError("mark_read permanently broken")

                on_valid_request = MagicMock()
                watcher = _make_watcher(gmail, store, on_valid_request=on_valid_request)
                watcher.poll_once()
                total_calls += on_valid_request.call_count

            self.assertEqual(total_calls, 1, "message was reprocessed after a simulated restart")


if __name__ == "__main__":
    unittest.main()
