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

_MARKER_RE = re.compile(
    r"^\s*(on .+ wrote:\s*$|--\s*$|—\s*$)", re.IGNORECASE | re.MULTILINE
)


def _strip_quoted_lines(body: str) -> str:
    return "\n".join(line for line in body.splitlines() if not line.lstrip().startswith(">"))


def _above_first_marker(body: str) -> str:
    match = _MARKER_RE.search(body)
    if not match:
        return body
    return body[: match.start()]


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
