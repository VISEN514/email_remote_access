"""Runtime-selectable security level (PLAN.md "Selectable security levels").

Level 2 is today's system unchanged (sender must be authenticated AND on
`access.allowed_senders`). Level 1 drops the allow-list identity check --
any authenticated sender can attempt the phrase. This is a genuine
authentication-model downgrade (secret-only instead of identity+secret),
not a minor variant -- see PLAN.md's "Real security delta" section.

Lives in `StateStore` (not `config.yaml`) so a popup-driven level change
takes effect on `mail_watcher`'s next poll cycle without a service restart.
"""
import time

from state_store import StateStore

DEFAULT_LEVEL = 2  # hardcoded safe fallback -- never the more permissive 1
ROLLING_WINDOW_SECONDS = 3600
DEFAULT_L1_MAX_NEW_SENDERS_PER_HOUR = 15


class SecurityLevelStore:
    def __init__(
        self,
        store: StateStore,
        allowed_senders,
        max_new_senders_per_hour: int = DEFAULT_L1_MAX_NEW_SENDERS_PER_HOUR,
        default_level: int = DEFAULT_LEVEL,
    ):
        self.store = store
        self.allowed_senders = {s.lower() for s in allowed_senders}
        self.max_new_senders_per_hour = max_new_senders_per_hour
        # Used only to seed the state store's value the first time it's
        # ever read with nothing set (PLAN.md "Where the level lives") --
        # the caller passes config.access["default_security_level"] here.
        # If the caller doesn't pass one, this itself falls back to the
        # hardcoded-safe module constant, so a missing/omitted config value
        # NEVER silently resolves to the more permissive level 1 either way.
        self.default_level = default_level if default_level in (1, 2) else DEFAULT_LEVEL

    def get_level(self) -> int:
        data = self.store.read()
        return data.get("security_level", self.default_level)

    def get_since(self) -> float:
        data = self.store.read()
        return data.get("security_level_since", 0)

    def set_level(self, new_level: int, notifier=None):
        """Single atomic StateStore.update(): reads the old level from the
        SAME dict being mutated (not a separate prior read -- avoids a
        read-then-write race). `security_level_since` is updated ONLY when
        the level actually changes (old_level != new_level) -- an idempotent
        re-set (e.g. a redundant click on an already-selected popup segment)
        must NOT reset the staleness clock heartbeat's L1-too-long check
        depends on, or a single accidental re-click could suppress that
        detection indefinitely. Alerts only on a genuine transition INTO
        level 1 (old != 1 and new == 1) -- not on every call, not on an
        idempotent re-set, not on a transition OUT of 1."""
        now = time.time()
        entering_level_1 = False

        def mutate(data):
            nonlocal entering_level_1
            old_level = data.get("security_level", self.default_level)
            data["security_level"] = new_level
            if old_level != new_level:
                data["security_level_since"] = now
            entering_level_1 = old_level != 1 and new_level == 1
            return data

        self.store.update(mutate)

        if entering_level_1 and notifier is not None:
            notifier.send_security_level_alert(new_level)

    # -- L1 aggregate flood cap (rolling 1-hour window, dict keyed by sender
    # so repeat triggers from the SAME sender never inflate the distinct
    # count -- see PLAN.md's "Aggregate flood cap" section) -------------
    def record_new_sender_if_l1(self, sender: str):
        """No-op unless the current level is 1 AND sender is unknown (not
        allow-listed) -- allow-listed senders must never consume a slot in
        this count, or an active flood from other senders could get the
        owner's own address archived by this defense (PLAN.md's named
        self-DoS gap)."""
        sender = sender.lower()
        if self.get_level() != 1 or sender in self.allowed_senders:
            return

        now = time.time()

        def mutate(data):
            seen = data.setdefault("new_sender_last_seen", {})
            cutoff = now - ROLLING_WINDOW_SECONDS
            for key in [k for k, ts in seen.items() if ts <= cutoff]:
                del seen[key]
            seen[sender] = now
            return data

        self.store.update(mutate)

    def l1_new_sender_cap_exceeded(self) -> bool:
        now = time.time()
        cutoff = now - ROLLING_WINDOW_SECONDS
        data = self.store.read()
        seen = data.get("new_sender_last_seen", {})
        distinct_recent = sum(1 for ts in seen.values() if ts > cutoff)
        return distinct_recent > self.max_new_senders_per_hour
