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


# Real Gmail delivery appends TWO Received headers, not one, by the time a
# message lands in an inbox: an outer hop naming the receiving MTA (e.g.
# "by mx.google.com with SMTPS ...", as the message is accepted from the
# sending server) and then an INNERMOST, actually-newest internal-delivery
# hop ("by <internal GFE address/hex id> with SMTP id ...", as Gmail's
# frontend delivers it into the mailbox). Confirmed against real captured
# headers during field testing: position 0 is always this internal hop
# (an IPv6-looking or hex identifier, never a hostname), and the
# "by mx.google.com"-style hop that this check actually cares about sits at
# position 1. Checking ONLY position 0 (as an earlier version of this code
# did) rejects every genuine Gmail-to-Gmail message -- a self-inflicted
# false-negative, not a security feature.
_TRUSTED_RECEIVED_HOP_SEARCH_DEPTH = 2


def _received_top_hop_is_trusted(received_values: list[str], trusted_authserv_id: str) -> bool:
    # Deliberately parses the "by <host>" clause specifically, rather than a
    # substring search over the whole free-text line -- a naive substring
    # search is smugglable (an attacker-controlled HELO string or comment
    # elsewhere in the same Received line containing "google.com" would
    # otherwise pass even when the real receiving host isn't Google's MTA).
    #
    # Bounded to the top _TRUSTED_RECEIVED_HOP_SEARCH_DEPTH entries, not the
    # whole array: both of these hops are appended by Google's own MTA chain
    # during real delivery, and nothing an external sender controls can ever
    # get injected ABOVE them (Received headers are always prepended, newest
    # on top) -- so this preserves the original fail-closed guarantee
    # (scanning arbitrarily far down would defeat the point) while matching
    # Gmail's actual observed behavior.
    google_hosts = ("google.com", "mx.google.com", "gmail.com")
    for received_value in received_values[:_TRUSTED_RECEIVED_HOP_SEARCH_DEPTH]:
        match = RECEIVED_BY_RE.search(received_value)
        if not match:
            continue
        by_host = match.group(1).lower().rstrip(".")
        if by_host == trusted_authserv_id.lower() or any(
            by_host == h or by_host.endswith("." + h) for h in google_hosts
        ):
            return True
    return False


def check_authenticated(headers: list[dict], trusted_authserv_id: str) -> AuthVerdict:
    """headers = the Gmail API's payload.headers array, in the order Gmail returned it."""
    auth_results = _headers_by_name(headers, "Authentication-Results")
    received = _headers_by_name(headers, "Received")

    if not auth_results:
        return AuthVerdict(False, "no Authentication-Results header present")
    if not received:
        return AuthVerdict(False, "no Received header present")

    # Only the FIRST Authentication-Results entry is trusted -- this is the
    # one Gmail's own receiving MTA is expected to have added as the newest
    # (topmost) entry. We do not fall back to scanning the rest of the array:
    # an attacker-forged header of the same name sits further down the
    # stack, and scanning past position 0 would defeat the whole point of
    # this check. (Received headers are handled differently -- see
    # _received_top_hop_is_trusted's docstring for why that one legitimately
    # needs to look at the top TWO entries, not just one.)
    if not _first_authserv_id_matches(auth_results[0], trusted_authserv_id):
        return AuthVerdict(
            False,
            f"first Authentication-Results entry's authserv-id doesn't match "
            f"{trusted_authserv_id!r} (fail closed, not scanning further entries)",
        )

    if not _received_top_hop_is_trusted(received, trusted_authserv_id):
        return AuthVerdict(
            False,
            "Authentication-Results claimed a Gmail authserv-id but neither of the "
            "top Received hops corroborate it -- cross-check disagreement, fail closed",
        )

    verdicts = dict(VERDICT_RE.findall(auth_results[0].lower()))
    for mechanism in ("spf", "dkim", "dmarc"):
        if verdicts.get(mechanism) != "pass":
            return AuthVerdict(False, f"{mechanism}={verdicts.get(mechanism)!r}, not pass")

    return AuthVerdict(True, "spf/dkim/dmarc all pass, Gmail-authenticated")
