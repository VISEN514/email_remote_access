"""Gmail header trust boundary (PLAN.md mail watcher section).

Only the Authentication-Results / Received entries that Gmail's own receiving
MTA appended are trusted -- never a raw string match against a header of that
name, since any sender can forge one. Fails closed (rejects) on anything
ambiguous, including unexpected header ordering.
"""
import re

AUTH_RESULTS_RE = re.compile(r"^(?P<authserv_id>[^\s;]+)\s*;\s*(?P<rest>.*)$", re.DOTALL)
VERDICT_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)")
# Matches the "by <host>" clause of a Received header specifically, not any
# occurrence of a Google-owned substring anywhere in the free-text line
# (which an attacker could smuggle in via a HELO string or comment).
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)


class AuthVerdict:
    def __init__(self, ok: bool, reason: str):
        self.ok = ok
        self.reason = reason

    def __bool__(self):
        return self.ok


def _headers_by_name(headers: list[dict], name: str) -> list[str]:
    name = name.lower()
    return [h["value"] for h in headers if h["name"].lower() == name]


def _first_authserv_id_matches(value: str, trusted_authserv_id: str) -> bool:
    m = AUTH_RESULTS_RE.match(value.strip())
    if not m:
        return False
    return m.group("authserv_id").lower() == trusted_authserv_id.lower()


def _received_top_hop_is_trusted(received_value: str, trusted_authserv_id: str) -> bool:
    # The topmost Received header's "by" clause names the receiving MTA.
    # Deliberately parses the "by <host>" clause specifically, rather than a
    # substring search over the whole free-text line -- a naive substring
    # search is smugglable (an attacker-controlled HELO string or comment
    # elsewhere in the same Received line containing "google.com" would
    # otherwise pass even when the real receiving host isn't Google's MTA).
    match = RECEIVED_BY_RE.search(received_value)
    if not match:
        return False
    by_host = match.group(1).lower().rstrip(".")
    google_hosts = ("google.com", "mx.google.com", "gmail.com")
    return by_host == trusted_authserv_id.lower() or any(
        by_host == h or by_host.endswith("." + h) for h in google_hosts
    )


def check_authenticated(headers: list[dict], trusted_authserv_id: str) -> AuthVerdict:
    """headers = the Gmail API's payload.headers array, in the order Gmail returned it."""
    auth_results = _headers_by_name(headers, "Authentication-Results")
    received = _headers_by_name(headers, "Received")

    if not auth_results:
        return AuthVerdict(False, "no Authentication-Results header present")
    if not received:
        return AuthVerdict(False, "no Received header present")

    # Only the FIRST entry in each array is trusted -- this is the one Gmail's
    # own receiving MTA is expected to have added as the newest (topmost) entry.
    # We do not fall back to scanning the rest of the array: an attacker-forged
    # header of the same name sits further down the stack, and scanning past
    # position 0 would defeat the whole point of this check.
    if not _first_authserv_id_matches(auth_results[0], trusted_authserv_id):
        return AuthVerdict(
            False,
            f"first Authentication-Results entry's authserv-id doesn't match "
            f"{trusted_authserv_id!r} (fail closed, not scanning further entries)",
        )

    if not _received_top_hop_is_trusted(received[0], trusted_authserv_id):
        return AuthVerdict(
            False,
            "Authentication-Results claimed a Gmail authserv-id but the topmost "
            "Received hop doesn't corroborate it -- cross-check disagreement, fail closed",
        )

    verdicts = dict(VERDICT_RE.findall(auth_results[0].lower()))
    for mechanism in ("spf", "dkim", "dmarc"):
        if verdicts.get(mechanism) != "pass":
            return AuthVerdict(False, f"{mechanism}={verdicts.get(mechanism)!r}, not pass")

    return AuthVerdict(True, "spf/dkim/dmarc all pass, Gmail-authenticated")
