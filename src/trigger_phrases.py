"""Accepted trigger phrases (PLAN.md section 1). Case-insensitive exact
match against a trimmed message body line -- a trigger is a fixed-list
membership check, not a secret, so plain string comparison (no
constant-time compare needed) is correct here."""

ACCEPTED_TRIGGERS = {
    "tap me in", "bring me online", "requesting extraction", "open the channel",
    "standing by for uplink", "requesting a link-up", "send the signal",
    "ready to breach", "awaiting your signal", "patch me through",
    "requesting pickup", "unlock the gate", "requesting entry", "give me the signal",
    "requesting a channel", "need eyes on the system", "requesting handshake",
    "log me in", "requesting remote access", "access request", "initiate session",
    "requesting sign-in", "start remote session", "please authenticate me",
    "beginning access request", "requesting connection", "sign me in, please",
    "requesting authorization", "please grant access", "requesting login",
    "access needed", "please initiate access", "requesting credentials",
    "session request", "access", "unlock", "online", "connect", "authenticate", "signal",
}

# Remote rotate-phrase command (PLAN.md section 6) -- deliberately a
# separate, distinctly-worded set so it can't be confused with a login
# trigger by accident.
ROTATE_TRIGGERS = {"rotate phrase", "rotate the phrase", "rotate my phrase"}


def classify_trigger(normalized_body_line: str) -> str | None:
    """Returns 'login', 'rotate', or None (not a recognized trigger)."""
    if normalized_body_line in ROTATE_TRIGGERS:
        return "rotate"
    if normalized_body_line in ACCEPTED_TRIGGERS:
        return "login"
    return None
