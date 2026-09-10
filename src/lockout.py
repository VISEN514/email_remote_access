import time

from state_store import StateStore


class LockoutTracker:
    """Tracks failed verification attempts per (authenticated) sender and
    enforces a cooldown. Persisted to disk so a service crash/restart can't
    silently reset an attacker's strike count (PLAN.md Monitoring section).

    Only ever called with senders that already passed the Authentication-Results
    / Received cross-check (see auth_check.py) -- an unauthenticated spoof of an
    allowed sender's address never reaches this tracker, so it can't be used to
    lock out the real owner (PLAN.md Lockout section).
    """

    def __init__(self, store: StateStore, max_failed_attempts: int, lockout_minutes: int):
        self.store = store
        self.max_failed_attempts = max_failed_attempts
        self.lockout_seconds = lockout_minutes * 60

    def is_locked(self, sender: str) -> bool:
        data = self.store.read()
        entry = data.get("lockouts", {}).get(sender)
        if not entry:
            return False
        return time.time() < entry.get("locked_until", 0)

    def record_failure(self, sender: str) -> bool:
        """Returns True if this failure just triggered a new lockout."""
        now = time.time()
        just_locked = False

        def mutate(data):
            nonlocal just_locked
            lockouts = data.setdefault("lockouts", {})
            entry = lockouts.setdefault(sender, {"failures": [], "locked_until": 0})
            entry["failures"] = [t for t in entry["failures"] if now - t <= self.lockout_seconds]
            entry["failures"].append(now)
            if len(entry["failures"]) >= self.max_failed_attempts:
                entry["locked_until"] = now + self.lockout_seconds
                entry["failures"] = []
                just_locked = True
            return data

        self.store.update(mutate)
        return just_locked

    def record_success(self, sender: str):
        def mutate(data):
            lockouts = data.setdefault("lockouts", {})
            lockouts[sender] = {"failures": [], "locked_until": 0}
            return data

        self.store.update(mutate)
