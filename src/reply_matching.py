"""Multi-candidate reply-body matching (PLAN.md section 5, rev 5 fix).

Real mail clients auto-append signatures/quoted trailers to a reply, and
different clients quote differently (top-posting vs. bottom-posting, `>`
prefixes vs. "On ... wrote:" markers). Rather than committing to one parsing
strategy (which broke twice across rev 3 and rev 4), this builds several
independent normalized candidate extractions from the raw body and accepts a
match against ANY of them -- explicitly scoped to Gmail/Outlook/Apple Mail's
default top-posting behavior (the confirmed target client, per PLAN.md's
resolved open question), not claimed universal.
"""
import re
import secrets

# The "On ... wrote:" clause is DOTALL-matched (spans newlines) because
# Gmail wraps this line onto two lines whenever the date/sender text is
# long enough -- e.g. "On Sun, Sep 13, 2026 at 1:54 PM Operator Alpha
# <address>\r\nwrote:\r\n" (confirmed via real field-testing capture, not
# a hypothetical). A single-line-only regex (an earlier version of this
# pattern) never finds the marker in that case, silently degrading to
# "no marker found" -- which fed a real lockout-burning mismatch, since
# the un-sliced attribution line then survives in every candidate. Kept
# non-greedy ("wrote:" found at the FIRST opportunity after "on") and
# anchored to a line starting with "on" (MULTILINE ^) so it doesn't
# over-match into unrelated later text.
_MARKER_RE = re.compile(
    r"^\s*(on\b.*?wrote:[ \t]*$|--\s*$|—\s*$)", re.IGNORECASE | re.MULTILINE | re.DOTALL
)


def _strip_quoted_lines(body: str) -> str:
    return "\n".join(line for line in body.splitlines() if not line.lstrip().startswith(">"))


def _above_first_marker(body: str) -> str:
    # Regex $ (MULTILINE) matches immediately before \n, not before \r\n --
    # real mail bodies (this one included, per field-testing capture) use
    # \r\n line endings, so a marker regex anchored with a bare $ silently
    # fails to match a line ending in "...wrote:\r\n" even though it's
    # visually the same as "...wrote:\n". Normalizing line endings first
    # sidesteps this rather than patching every alternative in the regex.
    normalized_body = body.replace("\r\n", "\n").replace("\r", "\n")
    match = _MARKER_RE.search(normalized_body)
    if not match:
        return body
    return normalized_body[: match.start()]


def _normalize(text: str) -> str:
    return " ".join(text.split()).strip().casefold()


def build_candidates(raw_body: str) -> list[str]:
    """Returns normalized candidate texts (whitespace-collapsed, trimmed,
    lowercased) -- see module docstring for why several, not one."""
    whole = raw_body
    quote_stripped = _strip_quoted_lines(raw_body)
    above_marker = _above_first_marker(raw_body)

    seen = set()
    candidates = []
    for text in (whole, quote_stripped, above_marker):
        normalized = _normalize(text)
        if normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)
    return candidates


def reply_matches_suffix(raw_body: str, suffix: str) -> bool:
    """A match on ANY normalized candidate counts as success (PLAN.md rev 5).
    Uses secrets.compare_digest per candidate -- the suffix is never emailed
    anywhere, so there's no plaintext-exposure difference between candidates,
    only a false-negative-avoidance one."""
    normalized_suffix = _normalize(suffix)
    return any(
        secrets.compare_digest(candidate, normalized_suffix) for candidate in build_candidates(raw_body)
    )
