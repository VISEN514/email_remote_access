"""Pending-challenge / flood / rotation-cooldown state, layered on the
existing StateStore (PLAN.md section 5-7). All mutations go through
StateStore.update(), which is a single atomic read-modify-write under its
own in-process lock -- the same concurrency model already established and
reviewed for LockoutTracker and SessionBroker (mail_watcher.py runs one poll
cycle at a time, single-threaded, so there's no concurrent caller anyway;
this just means a check-and-consume can't race a second call within the same
process).
"""
import time

from reply_matching import reply_matches_suffix
from state_store import StateStore

CHALLENGE_EXPIRY_SECONDS = 5 * 60
ABANDONED_THRESHOLD_PER_HOUR = 10
ROTATION_COOLDOWN_SECONDS = 10 * 60


class ChallengeStore:
    def __init__(self, store: StateStore):
        self.store = store

    # -- pending challenge (one shared slot per sender, tagged by type) -----
    def get_pending(self, sender: str) -> dict | None:
        data = self.store.read()
        return data.get("pending_challenges", {}).get(sender)

    def try_create(self, sender: str, challenge_type: str, prefix: str, suffix: str) -> bool:
        """Returns True if a challenge was created, False if rejected because
        a non-expired, unconsumed challenge already occupies this sender's
        slot (PLAN.md section 5: reject-not-replace, not a silent clobber)."""
        now = time.time()
        created = False

        def mutate(data):
            nonlocal created
            pending = data.setdefault("pending_challenges", {})
            existing = pending.get(sender)
            if existing and not existing["consumed"] and existing["expires_at"] > now:
                return data  # slot occupied -- reject, do not replace
            pending[sender] = {
                "type": challenge_type,
                "prefix": prefix,
                "suffix": suffix,
                "issued_at": now,
                "expires_at": now + CHALLENGE_EXPIRY_SECONDS,
                "consumed": False,
                # Distinct from "consumed": a wrong-suffix reply is answered
                # (lockout already accounts for it) but not a match -- it
                # must NOT also count as "abandoned" toward section 7's
                # threshold when it later expires. See sweep_expired().
                "answered": False,
            }
            created = True
            return data

        self.store.update(mutate)
        return created

    def try_consume(self, sender: str, raw_reply_body: str) -> tuple[str, str | None, str | None]:
        """Atomically checks-and-consumes: is there a non-expired,
        unconsumed challenge for this sender, and does any normalized
        candidate extraction of raw_reply_body match its suffix?

        Returns (result, challenge_type, suffix): result is one of 'match',
        'mismatch', 'no_pending'; challenge_type ('login'/'rotate') and
        suffix (the challenge's own suffix, as issued -- so the caller can
        e.g. infer which phrase STYLE was active for that challenge without
        a second, separately-racing read of "the current phrase", which
        could have since rotated) are set only when result == 'match'. On
        'match', the challenge is marked consumed in this SAME operation, so
        a second, replayed, or racing reply for the same challenge finds
        'no_pending'. On 'mismatch', the challenge is marked ANSWERED (but
        not consumed) in this same operation -- PLAN.md section 6/7: a
        challenge that got ANY reply, right or wrong, was answered, not
        abandoned, and must never count toward section 7's abandoned-trigger
        flood threshold. It stays available for a further retry reply until
        it actually expires."""
        now = time.time()
        result = "no_pending"
        challenge_type = None
        challenge_suffix = None

        def mutate(data):
            nonlocal result, challenge_type, challenge_suffix
            pending = data.setdefault("pending_challenges", {})
            existing = pending.get(sender)
            if not existing or existing["consumed"] or existing["expires_at"] <= now:
                result = "no_pending"
                return data
            if reply_matches_suffix(raw_reply_body, existing["suffix"]):
                existing["consumed"] = True
                result = "match"
                challenge_type = existing["type"]
                challenge_suffix = existing["suffix"]
            else:
                existing["answered"] = True
                result = "mismatch"
            return data

        self.store.update(mutate)
        return result, challenge_type, challenge_suffix

    # -- expiry sweep + abandoned-trigger flood defense (section 7) --------
    def sweep_expired(self) -> list[str]:
        """Clears any pending challenge past its expiry. Only a challenge
        that got NO reply at all (never 'answered' -- see try_consume) before
        expiring is recorded toward the dedicated abandoned-trigger
        threshold: a wrong-suffix reply is answered, not abandoned, and must
        not double as a free entry in this separate counter (PLAN.md section
        6/7). Returns the list of senders whose threshold was JUST tripped by
        this sweep (for alerting, once per crossing)."""
        now = time.time()
        tripped = []

        def mutate(data):
            pending = data.setdefault("pending_challenges", {})
            abandoned = data.setdefault("abandoned_events", {})
            for sender, challenge in list(pending.items()):
                if challenge["expires_at"] > now:
                    continue
                if not challenge["consumed"] and not challenge.get("answered", False):
                    events = abandoned.setdefault(sender, [])
                    events[:] = [t for t in events if now - t <= 3600]
                    before = len(events)
                    events.append(now)
                    # Trip on the crossing (before < threshold <= after), not
                    # on every sweep that happens to be at-or-above it --
                    # that would re-alert on every single abandoned event
                    # once above threshold. Using a crossing check (rather
                    # than `== threshold`) is also safe if `events` is ever
                    # seeded above threshold by other means (e.g. a restored
                    # state file), unlike a bare equality check.
                    if before < ABANDONED_THRESHOLD_PER_HOUR <= len(events):
                        tripped.append(sender)
                del pending[sender]
            return data

        self.store.update(mutate)
        return tripped

    def clear_pending(self, sender: str):
        """Physical-access-only 'clear stuck pending challenge' action
        (PLAN.md section 4's popup button)."""
        def mutate(data):
            data.setdefault("pending_challenges", {}).pop(sender, None)
            return data

        self.store.update(mutate)

    # -- rotation cooldown (section 6) --------------------------------------
    def rotation_on_cooldown(self, sender: str) -> bool:
        data = self.store.read()
        last = data.get("last_rotation_success", {}).get(sender, 0)
        return time.time() - last < ROTATION_COOLDOWN_SECONDS

    def record_rotation_success(self, sender: str):
        now = time.time()

        def mutate(data):
            data.setdefault("last_rotation_success", {})[sender] = now
            return data

        self.store.update(mutate)
