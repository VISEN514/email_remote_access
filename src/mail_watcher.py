import logging
import time
from email.utils import parseaddr

from auth_check import check_authenticated
from challenge_store import ChallengeStore
from gmail_client import GmailClient
from lockout import LockoutTracker
from phrase_manager import Passphrase, PhraseManager, style_of
from reply_matching import build_candidates
from security_level_store import SecurityLevelStore
from state_store import StateStore
from trigger_phrases import classify_trigger

_MAX_REMEMBERED_HANDLED_IDS = 2000

logger = logging.getLogger("mail_watcher")


def _extract_sender(headers: list[dict]) -> str | None:
    """Uses email.utils.parseaddr to get the REAL RFC 5322 address, not a
    naive regex match against the raw header text. A naive first-match regex
    is exploitable: 'From: "av.oct15@gmail.com" <attacker@evil.com>' would
    regex-match the address in the display name (which the allow-list
    trusts) while DKIM/DMARC legitimately authenticates the angle-bracket
    address (attacker@evil.com) -- parseaddr always extracts the real
    angle-bracket address, which is the one DKIM/DMARC actually authenticate,
    so a decoy display name can't smuggle an allow-listed string past this."""
    for h in headers:
        if h["name"].lower() == "from":
            _display_name, addr = parseaddr(h["value"])
            return addr.lower() if addr else None
    return None


def _first_nonblank_line(body: str) -> str:
    """The trigger check looks at the first non-blank line only, normalized
    -- a trigger phrase is meant to be the entire message, but tolerating a
    trailing blank line or a mobile client's auto-added blank line before a
    signature shouldn't turn a valid trigger into 'unrecognized'. This is
    deliberately narrower than reply_matching's multi-candidate suffix
    extraction: a trigger is checked for EXACT membership in a small fixed
    list (no quoting/signature ambiguity to resolve, since it's the first
    line of a fresh, not-yet-replied-to message), so one normalized
    candidate is sufficient and correct here."""
    for line in body.splitlines():
        stripped = " ".join(line.split()).strip().casefold()
        if stripped:
            return stripped
    return ""


class MailWatcher:
    def __init__(
        self,
        gmail: GmailClient,
        access_config: dict,
        flood_config: dict,
        trusted_authserv_id: str,
        lockout: LockoutTracker,
        phrase_manager: PhraseManager,
        challenges: ChallengeStore,
        security_level_store: SecurityLevelStore,
        on_valid_request,
        on_rotation,
        on_abandoned_flood,
        handled_ids_store: StateStore,
    ):
        self.gmail = gmail
        self.allowed_senders = {s.lower() for s in access_config["allowed_senders"]}
        self.trusted_authserv_id = trusted_authserv_id
        self.lockout = lockout
        self.phrase_manager = phrase_manager
        self.challenges = challenges
        self.security_level_store = security_level_store
        # on_valid_request(sender, valid, just_locked): fired for a login
        # challenge's suffix reply (match or mismatch) -- unchanged
        # signature/semantics from v1, still owns session start + rotation.
        self.on_valid_request = on_valid_request
        # on_rotation(sender, style): fired when a rotate-confirmation
        # challenge's suffix reply matches AND the rotation cooldown has
        # elapsed -- generates+emails a new random phrase.
        self.on_rotation = on_rotation
        # on_abandoned_flood(sender): fired (once per threshold crossing)
        # when a sender's abandoned-challenge count trips section 7's
        # dedicated threshold -- reports a degraded heartbeat state.
        self.on_abandoned_flood = on_abandoned_flood
        self.flood_threshold = flood_config["threshold_per_cycle"]
        self.trash_instead_of_archive = flood_config.get("trash_instead_of_archive", False)
        self.default_style = access_config.get("default_phrase_style", "diceware")
        # Persisted, not just in-memory: if mark_read itself permanently
        # fails for a message whose side effects already committed (see
        # _mark_read_best_effort), that message stays UNREAD in Gmail
        # forever and would otherwise be fetched and reprocessed every
        # single cycle -- double-firing record_success/record_failure/
        # on_valid_request each time. This set is the actual mechanism that
        # prevents that: once a message's side effects are committed, its
        # id is remembered here regardless of whether mark_read succeeded,
        # and _handle_allowed_sender is never invoked for it again. Persisted
        # (not just in-memory) so a service restart doesn't forget and
        # reprocess a message stuck in this exact state.
        self.handled_ids_store = handled_ids_store

    def poll_once(self) -> bool:
        """Returns True if the cycle completed successfully (for heartbeat purposes)."""
        try:
            # Sweep expired pending challenges FIRST, before processing this
            # cycle's messages -- this is what frees a sender's slot for a
            # new trigger in this same cycle, and what feeds section 7's
            # abandoned-trigger flood threshold.
            tripped = self.challenges.sweep_expired()
            for sender in tripped:
                logger.warning(
                    "Abandoned-challenge flood threshold tripped for %s (10+ unreplied "
                    "challenges within an hour) -- reporting degraded heartbeat state",
                    sender,
                )
                self.on_abandoned_flood(sender)

            # Read the security level ONCE, at the top of the cycle -- not
            # per-message. A change mid-cycle (from the popup) must never
            # split policy within the same batch of messages (see PLAN.md's
            # "Selectable security levels" -- this is the exact race an
            # inline per-message read would introduce).
            security_level = self.security_level_store.get_level()

            msg_ids = self.gmail.list_unread_ids()
            to_archive: list[str] = []

            already_handled = set(self.handled_ids_store.read().get("handled_message_ids", []))

            for msg_id in msg_ids:
                if msg_id in already_handled:
                    # Side effects for this message were already committed
                    # on a prior cycle (mark_read must have failed then, or
                    # we'd never have seen it as unread again) -- do NOT
                    # reprocess it. Just keep trying to mark it read so it
                    # eventually stops needing this check at all.
                    self._mark_read_best_effort(msg_id)
                    continue

                headers = self.gmail.get_headers(msg_id)

                sender = _extract_sender(headers)
                verdict = check_authenticated(headers, self.trusted_authserv_id)

                if not verdict.ok:
                    logger.info("Rejected message (unauthenticated): %s", verdict.reason)
                    to_archive.append(msg_id)
                    continue

                if security_level == 2 and sender not in self.allowed_senders:
                    logger.info("Rejected message: authenticated sender %s not on allow-list", sender)
                    to_archive.append(msg_id)
                    continue

                # Level 1 only (cheap no-op at level 2 or for an
                # allow-listed sender): track this sender toward the
                # rolling distinct-new-sender flood cap. Allow-listed
                # senders are exempt so the owner's own address can never
                # be counted against -- or archived by -- a defense that
                # exists solely to bound UNKNOWN senders' behavior.
                self.security_level_store.record_new_sender_if_l1(sender)
                if (
                    security_level == 1
                    and sender not in self.allowed_senders
                    and self.security_level_store.l1_new_sender_cap_exceeded()
                    and self.challenges.get_pending(sender) is None
                ):
                    logger.warning(
                        "Level 1 new-sender flood cap exceeded -- rejecting trigger from "
                        "never-before-seen sender %s without issuing a challenge",
                        sender,
                    )
                    to_archive.append(msg_id)
                    continue

                # mark_read for this path fires immediately (one call per
                # message), not batched at cycle end -- but critically, only
                # AFTER _handle_allowed_sender has fully completed its side
                # effects (lockout bookkeeping, challenge creation/consumption,
                # session start, notification), never before. See the
                # extended reasoning in the docstring-length comment this
                # replaced in the v1 revision of this file (git history) --
                # unchanged principle, just re-applied to the new two-step
                # flow: any exception inside _handle_allowed_sender leaves
                # the message unread and safely reprocessed next cycle
                # (nothing committed yet for THIS message); success marks it
                # handled+read immediately, before a later message's
                # unrelated failure could abort the cycle.
                handled = self._handle_allowed_sender(msg_id, sender)
                self._remember_handled(msg_id)
                self._mark_read_best_effort(msg_id)

                if not handled:
                    # Locked-out sender, or a rejected/unrecognized message
                    # (trigger while a slot is occupied, reply with no
                    # pending challenge, or plain unrecognized text): don't
                    # accumulate unread-forever in INBOX -- archive it like
                    # any other rejected message. Lockout/flood bookkeeping
                    # for WHY it wasn't handled already happened inside
                    # _handle_allowed_sender.
                    to_archive.append(msg_id)

            if len(to_archive) >= self.flood_threshold:
                logger.warning("Flood threshold exceeded this cycle (%d messages)", len(to_archive))

            # Batched here, not per-message: these are exactly the messages
            # that have NO side effect tied to phrase/lockout state (spam,
            # unauthenticated, already-locked-out senders, or rejected/
            # unrecognized allowed-sender mail), so they're safe to leave
            # unread-and-reprocessed if the cycle aborts, and batching is
            # what actually matters for flood-volume API cost.
            self.gmail.batch_archive(to_archive, trash_instead=self.trash_instead_of_archive)

            return True
        except Exception:
            logger.exception("Poll cycle failed")
            return False

    def _mark_read_best_effort(self, msg_id: str, attempts: int = 3, backoff_seconds: float = 1.0):
        for attempt in range(1, attempts + 1):
            try:
                self.gmail.mark_read(msg_id)
                return
            except Exception:
                logger.exception("mark_read attempt %s/%s failed for %s", attempt, attempts, msg_id)
                if attempt < attempts:
                    time.sleep(backoff_seconds)
        logger.critical(
            "mark_read permanently failed for %s. Its side effects (if any) were already "
            "committed and its id is recorded in the handled-ids store, so it will NOT be "
            "reprocessed on future cycles despite staying unread in Gmail. Archive or mark "
            "it read by hand to clear the stuck state.",
            msg_id,
        )

    def _remember_handled(self, msg_id: str):
        def mutate(data):
            ids = data.get("handled_message_ids", [])
            ids.append(msg_id)
            if len(ids) > _MAX_REMEMBERED_HANDLED_IDS:
                ids = ids[-_MAX_REMEMBERED_HANDLED_IDS:]
            return {**data, "handled_message_ids": ids}

        self.handled_ids_store.update(mutate)

    def _handle_allowed_sender(self, msg_id: str, sender: str) -> bool:
        """Returns True if the message was handled as a live request (a
        recognized trigger that issued a challenge, or a reply that was
        checked as a match/mismatch against a pending challenge); False if
        it should be archived without further action (locked-out sender, a
        trigger while the slot is occupied, a reply with no pending
        challenge, or genuinely unrecognized text)."""
        if self.lockout.is_locked(sender):
            logger.info("Ignoring message from locked-out sender %s", sender)
            return False

        body = self.gmail.get_body_text(msg_id)
        first_line = _first_nonblank_line(body)
        trigger_kind = classify_trigger(first_line)

        if trigger_kind is not None:
            return self._handle_trigger(sender, trigger_kind)

        return self._handle_reply(sender, body)

    def _handle_trigger(self, sender: str, trigger_kind: str) -> bool:
        """PLAN.md section 5 step 1-3 / section 6: sender already
        authenticated by the caller. A trigger is not lockout-gated (it's
        not secret), and a REJECTED trigger (slot occupied) is likewise not
        lockout-gated -- only a wrong SUFFIX reply ever burns a lockout
        strike (see _handle_reply)."""
        current = self.phrase_manager.current_phrase()
        created = self.challenges.try_create(
            sender, challenge_type=trigger_kind, prefix=current.prefix, suffix=current.suffix
        )
        if not created:
            logger.info(
                "Rejected %s trigger from %s: a challenge is already pending for this sender "
                "(reject-not-replace, PLAN.md section 5)",
                trigger_kind,
                sender,
            )
            return False

        logger.info("Issued %s challenge to %s: disclosed prefix %r", trigger_kind, sender, current.prefix)
        self.on_valid_request(sender=sender, valid=None, just_locked=False, challenge_prefix=current.prefix)
        return True

    def _handle_reply(self, sender: str, body: str) -> bool:
        """PLAN.md section 5 step 4 / section 6: atomic check-and-consume
        against whatever challenge (login or rotate) is pending for this
        sender."""
        result, challenge_type, challenge_suffix = self.challenges.try_consume(sender, body)

        if result == "no_pending":
            logger.info("Ignoring reply from %s: no pending challenge (expired or never issued)", sender)
            return False

        if result == "mismatch":
            logger.info("Rejected suffix reply from %s: mismatch", sender)
            just_locked = self.lockout.record_failure(sender)
            self.on_valid_request(sender=sender, valid=False, just_locked=just_locked, challenge_prefix=None)
            return True

        # result == "match"
        self.lockout.record_success(sender)
        if challenge_type == "rotate":
            logger.info("Rotate-confirmation matched for %s", sender)
            # Infer style from the CHALLENGED phrase's own suffix (captured
            # at issuance), not config's default_phrase_style and not a
            # fresh phrase_manager.current_phrase() read -- preserves
            # whichever style the owner is actually using that day rather
            # than silently reverting it on every remote rotation.
            style = style_of(Passphrase(prefix="", suffix=challenge_suffix)) if challenge_suffix else self.default_style
            self.on_rotation(sender=sender, style=style)
        else:
            logger.info("Login challenge matched for %s", sender)
            self.on_valid_request(sender=sender, valid=True, just_locked=False, challenge_prefix=None)
        return True
