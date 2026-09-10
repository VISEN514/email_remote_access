"""Crash-safe phrase rotation (PLAN.md Phrase lifecycle section).

Ordering is deliberate and load-bearing:
  1. validate request against the CURRENT active phrase (phrase.txt)
  2. generate a candidate next phrase, write it to phrase.next (not yet live)
  3. caller attempts to start the session -- if that fails, abort: phrase.next
     is discarded, phrase.txt (old phrase) is untouched, nothing is stranded
  4. once the tunnel is live, rename phrase.next -> phrase.txt FIRST
  5. only after the rename is confirmed does the caller send the notification
     email containing the new phrase

Rename-before-notify (not notify-before-rename) is the specific fix for the
self-lockout race identified in PLAN.md's review log: a crash between the two
steps leaves the owner not-yet-informed of a phrase that IS live, rather than
informed of a phrase that ISN'T -- the former can't burn real lockout strikes,
the latter would.

v2 (PLAN.md rev 7) replaces the opaque 256-bit token with a human-readable,
asymmetrically-split passphrase: a 2-word disclosed prefix (given away on
every trigger, so its entropy doesn't matter) + a per-style undisclosed
suffix sized to a real ~40+ bit floor (diceware: 4 words from EFF's 7776-word
list =~ 51.6 bits; tactical: 7 words from the ~86-word NATO+tactical pool
=~ 44.9 bits -- see PLAN.md section 2 for why equal word-count would NOT mean
equal entropy across styles). Per-login rotation is gone (PLAN.md section 3);
`current_phrase`/`stage_next_phrase`/`commit_staged`/`discard_staged` remain
for the scheduled/on-demand/remote rotation paths, which are unchanged.
"""
import os
import secrets
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from file_perms import restrict_to_current_user
from wordlists import NATO_ALPHABET, TACTICAL_POOL, load_eff_wordlist

PREFIX_WORD_COUNT = 2
DICEWARE_SUFFIX_WORD_COUNT = 4  # 4 * log2(7776) =~ 51.6 bits
TACTICAL_SUFFIX_WORD_COUNT = 7  # 7 * log2(86)   =~ 44.9 bits

STYLES = ("diceware", "tactical")


def style_of(phrase: "Passphrase") -> str:
    """Infers which style a phrase was generated/entered as, from its
    suffix word count -- used so remote rotation (PLAN.md section 6) can
    preserve the owner's current style instead of silently reverting to
    whatever config.access.default_phrase_style happens to be, which could
    be a different style than the one actually in use that day. Falls back
    to 'diceware' for a word count that matches neither style (shouldn't
    happen for a phrase this class generated, but a hand-edited phrase.txt
    could in principle produce one)."""
    word_count = len(phrase.suffix.split())
    if word_count == TACTICAL_SUFFIX_WORD_COUNT:
        return "tactical"
    return "diceware"


@dataclass(frozen=True)
class Passphrase:
    """The two halves of a passphrase, kept distinct so callers can never
    accidentally treat the disclosed prefix as secret or vice versa."""
    prefix: str  # disclosed on every trigger -- not secret by design
    suffix: str  # never disclosed except in the owner's own reply

    @property
    def full(self) -> str:
        return f"{self.prefix} {self.suffix}"

    def __repr__(self) -> str:
        # The suffix is the single most sensitive value in this system and
        # must never appear in a log line, traceback, or notifier message
        # via an accidental bare-object interpolation (e.g. an f-string
        # that forgot ".prefix"/".suffix"/".full" and used the object
        # itself). Overriding the dataclass's default all-fields __repr__
        # is a structural guard against that class of leak, not just a
        # style choice.
        return f"Passphrase(prefix={self.prefix!r}, suffix=<redacted, {len(self.suffix.split())} words>)"

    __str__ = __repr__

    @staticmethod
    def parse(raw: str, suffix_word_count: int) -> "Passphrase":
        """Splits a normalized full phrase into prefix/suffix by word count
        -- the LAST `suffix_word_count` words are the suffix, and the
        remaining words must be EXACTLY `PREFIX_WORD_COUNT` (2), not merely
        'more than 0': PLAN.md section 4 fixes the disclosed prefix at 2
        words specifically, and silently accepting a longer prefix would
        shrink the effective secret (more words disclosed) while the owner
        reasonably believes the phrase has the intended 2+N shape."""
        words = raw.split()
        if len(words) != PREFIX_WORD_COUNT + suffix_word_count:
            raise ValueError(
                f"Phrase must have exactly {PREFIX_WORD_COUNT + suffix_word_count} words "
                f"({PREFIX_WORD_COUNT}-word prefix + {suffix_word_count}-word suffix), got {len(words)}"
            )
        prefix = " ".join(words[:PREFIX_WORD_COUNT])
        suffix = " ".join(words[PREFIX_WORD_COUNT:])
        return Passphrase(prefix=prefix, suffix=suffix)


def normalize_phrase_text(raw: str) -> str:
    """Unicode NFC normalization + whitespace collapse + case-fold, applied
    identically to custom popup input and to the stored phrase, so a stray
    trailing space or a homoglyph typed by hand can't cause a mismatch or a
    false sense of a stronger phrase than was actually typed (PLAN.md
    section 4)."""
    text = unicodedata.normalize("NFC", raw)
    text = " ".join(text.split())
    return text.casefold()


class PhraseManager:
    def __init__(self, phrase_path: str, phrase_next_path: str):
        self.phrase_path = Path(phrase_path)
        self.phrase_next_path = Path(phrase_next_path)
        self.phrase_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.phrase_path.exists():
            self._write_atomic(self.phrase_path, self._encode(self.generate_random("diceware")))

    # -- generation --------------------------------------------------------
    @staticmethod
    def generate_random(style: str) -> Passphrase:
        if style not in STYLES:
            raise ValueError(f"Unknown style {style!r}, must be one of {STYLES}")

        prefix_words = [secrets.choice(NATO_ALPHABET) for _ in range(PREFIX_WORD_COUNT)]
        prefix = " ".join(prefix_words)

        if style == "diceware":
            pool = load_eff_wordlist()
            suffix_words = [secrets.choice(pool) for _ in range(DICEWARE_SUFFIX_WORD_COUNT)]
        else:
            suffix_words = [secrets.choice(TACTICAL_POOL) for _ in range(TACTICAL_SUFFIX_WORD_COUNT)]
        suffix = " ".join(suffix_words)

        return Passphrase(prefix=normalize_phrase_text(prefix), suffix=normalize_phrase_text(suffix))

    @staticmethod
    def from_custom_input(raw: str, style: str) -> Passphrase:
        """Popup's custom-phrase path (PLAN.md section 4): normalize first,
        then split by the style's expected suffix word count."""
        if style not in STYLES:
            raise ValueError(f"Unknown style {style!r}, must be one of {STYLES}")
        suffix_word_count = DICEWARE_SUFFIX_WORD_COUNT if style == "diceware" else TACTICAL_SUFFIX_WORD_COUNT
        normalized = normalize_phrase_text(raw)
        return Passphrase.parse(normalized, suffix_word_count)

    # -- encoding on disk ----------------------------------------------------
    # Stored as "prefix\nsuffix" -- explicit, unambiguous, and avoids ever
    # having to re-guess the prefix/suffix boundary from stored text (the
    # word-count boundary depends on which style generated it, which isn't
    # otherwise recorded).
    @staticmethod
    def _encode(phrase: Passphrase) -> str:
        return f"{phrase.prefix}\n{phrase.suffix}"

    @staticmethod
    def _decode(raw: str) -> Passphrase:
        # rstrip a single trailing newline defensively -- _write_atomic never
        # appends one, but a stray trailing blank line from any tool that
        # ever touches this file directly (an editor's auto-newline-on-save,
        # a manual `type con >> phrase.txt`) shouldn't turn into a hard
        # ValueError on the very next read of the single most load-bearing
        # file in the system.
        lines = raw.rstrip("\r\n").splitlines()
        if len(lines) != 2:
            raise ValueError(f"Malformed phrase file: expected 2 lines, got {len(lines)}")
        return Passphrase(prefix=lines[0], suffix=lines[1])

    @staticmethod
    def _write_atomic(path: Path, content: str):
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise
        restrict_to_current_user(str(path))

    # -- current/staged phrase lifecycle -------------------------------------
    def current_phrase(self) -> Passphrase:
        return self._decode(self.phrase_path.read_text(encoding="utf-8"))

    def stage_next_phrase(self, style: str = "diceware") -> Passphrase:
        """Step 2: write a candidate next phrase, not yet active."""
        candidate = self.generate_random(style)
        self._write_atomic(self.phrase_next_path, self._encode(candidate))
        return candidate

    def stage_custom_phrase(self, raw: str, style: str) -> Passphrase:
        """Popup's custom-phrase path -- stages rather than writing directly,
        so it goes through the same commit/discard machinery as a generated
        phrase (same file permissions and atomicity guarantees, per PLAN.md
        section 4)."""
        candidate = self.from_custom_input(raw, style)
        self._write_atomic(self.phrase_next_path, self._encode(candidate))
        return candidate

    def discard_staged(self):
        """Step 3 abort path: session start failed, old phrase stays live."""
        if self.phrase_next_path.exists():
            self.phrase_next_path.unlink()

    def commit_staged(self):
        """Step 4: atomically promote phrase.next -> phrase.txt. Must be
        called BEFORE sending the notification email (see module docstring)."""
        if not self.phrase_next_path.exists():
            raise RuntimeError("No staged phrase to commit -- call stage_next_phrase() first")
        os.replace(self.phrase_next_path, self.phrase_path)

    def physical_reset(self, style: str = "diceware") -> Passphrase:
        """Local, physical-access-only reset path (run by hand on the laptop's
        own keyboard, or via the popup). Not reachable remotely -- there is
        no email/network trigger that calls THIS method; the remote
        rotate-phrase command uses remote_rotate() below instead, which does
        the identical write but is invoked only after passing the full
        challenge/response cycle (PLAN.md section 6), not merely on request."""
        new_phrase = self.generate_random(style)
        self._write_atomic(self.phrase_path, self._encode(new_phrase))
        self.discard_staged()
        return new_phrase

    def remote_rotate(self, style: str = "diceware") -> Passphrase:
        """Remote rotate-phrase command's write path (PLAN.md section 6) --
        called only after the caller has already verified a correct suffix
        reply to a rotate-confirmation challenge AND checked the 10-minute
        cooldown; this method itself does neither check, it just performs
        the same direct generate-and-write as physical_reset()."""
        new_phrase = self.generate_random(style)
        self._write_atomic(self.phrase_path, self._encode(new_phrase))
        self.discard_staged()
        return new_phrase

    def set_custom_phrase(self, raw: str, style: str) -> Passphrase:
        """Popup's direct custom-phrase write (bypassing stage/commit, for
        the local-only popup path where there's no in-flight session to
        protect against -- same atomic-write mechanism as physical_reset)."""
        new_phrase = self.from_custom_input(raw, style)
        self._write_atomic(self.phrase_path, self._encode(new_phrase))
        self.discard_staged()
        return new_phrase
