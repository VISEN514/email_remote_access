import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import math
import tempfile
import unittest

from phrase_manager import (
    DICEWARE_SUFFIX_WORD_COUNT,
    PREFIX_WORD_COUNT,
    TACTICAL_SUFFIX_WORD_COUNT,
    PhraseManager,
    Passphrase,
    normalize_phrase_text,
)
from wordlists import TACTICAL_POOL, load_eff_wordlist


class TestPhraseManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.phrase_path = Path(self.tmpdir.name) / "phrase.txt"
        self.next_path = Path(self.tmpdir.name) / "phrase.next"
        self.pm = PhraseManager(str(self.phrase_path), str(self.next_path))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_initial_phrase_created_with_prefix_and_suffix(self):
        self.assertTrue(self.phrase_path.exists())
        current = self.pm.current_phrase()
        self.assertEqual(len(current.prefix.split()), PREFIX_WORD_COUNT)
        self.assertEqual(len(current.suffix.split()), DICEWARE_SUFFIX_WORD_COUNT)

    def test_diceware_suffix_words_come_from_eff_list(self):
        pool = set(load_eff_wordlist())
        phrase = PhraseManager.generate_random("diceware")
        for word in phrase.suffix.split():
            self.assertIn(word, pool)
        self.assertEqual(len(phrase.suffix.split()), DICEWARE_SUFFIX_WORD_COUNT)

    def test_tactical_suffix_words_come_from_combined_pool(self):
        pool = set(TACTICAL_POOL)
        phrase = PhraseManager.generate_random("tactical")
        for word in phrase.suffix.split():
            self.assertIn(word, pool)
        self.assertEqual(len(phrase.suffix.split()), TACTICAL_SUFFIX_WORD_COUNT)

    def test_entropy_floor_is_actually_met_per_style(self):
        # PLAN.md section 2's arithmetic, verified against the actual pools
        # used by generate_random, not just asserted in prose.
        diceware_bits = DICEWARE_SUFFIX_WORD_COUNT * math.log2(len(load_eff_wordlist()))
        tactical_bits = TACTICAL_SUFFIX_WORD_COUNT * math.log2(len(TACTICAL_POOL))
        self.assertGreaterEqual(diceware_bits, 40)
        self.assertGreaterEqual(tactical_bits, 40)

    def test_unknown_style_rejected(self):
        with self.assertRaises(ValueError):
            PhraseManager.generate_random("nonexistent-style")

    def test_abort_path_leaves_old_phrase_live(self):
        old = self.pm.current_phrase()
        self.pm.stage_next_phrase()
        self.pm.discard_staged()
        self.assertEqual(self.pm.current_phrase(), old)
        self.assertFalse(self.next_path.exists())

    def test_commit_rotates_phrase(self):
        old = self.pm.current_phrase()
        new = self.pm.stage_next_phrase()
        self.pm.commit_staged()
        self.assertEqual(self.pm.current_phrase(), new)
        self.assertNotEqual(self.pm.current_phrase(), old)
        self.assertFalse(self.next_path.exists())

    def test_commit_without_stage_raises(self):
        with self.assertRaises(RuntimeError):
            self.pm.commit_staged()

    def test_physical_reset_discards_any_staged_phrase(self):
        self.pm.stage_next_phrase()
        reset_phrase = self.pm.physical_reset()
        self.assertEqual(self.pm.current_phrase(), reset_phrase)
        self.assertFalse(self.next_path.exists())

    def test_remote_rotate_discards_any_staged_phrase(self):
        self.pm.stage_next_phrase()
        rotated = self.pm.remote_rotate()
        self.assertEqual(self.pm.current_phrase(), rotated)
        self.assertFalse(self.next_path.exists())


class TestCustomPhraseNormalization(unittest.TestCase):
    def test_normalize_collapses_whitespace_trims_and_casefolds(self):
        self.assertEqual(normalize_phrase_text("  Bravo   Six\tgoing\ndark  "), "bravo six going dark")

    def test_normalize_is_idempotent(self):
        once = normalize_phrase_text("Bravo Six Going Dark")
        twice = normalize_phrase_text(once)
        self.assertEqual(once, twice)

    def test_from_custom_input_splits_by_style_suffix_length(self):
        raw = "Bravo Six going dark echo delta hotel signal breach"  # 2 prefix + 7 suffix
        phrase = PhraseManager.from_custom_input(raw, "tactical")
        self.assertEqual(phrase.prefix, "bravo six")
        self.assertEqual(phrase.suffix, "going dark echo delta hotel signal breach")

    def test_from_custom_input_too_short_raises(self):
        with self.assertRaises(ValueError):
            PhraseManager.from_custom_input("only two", "diceware")

    def test_set_custom_phrase_writes_directly_and_discards_staged(self):
        tmpdir = tempfile.TemporaryDirectory()
        try:
            phrase_path = Path(tmpdir.name) / "phrase.txt"
            next_path = Path(tmpdir.name) / "phrase.next"
            pm = PhraseManager(str(phrase_path), str(next_path))
            pm.stage_next_phrase()
            raw = "bravo six correct horse battery staple"  # 2 prefix + 4 suffix
            result = pm.set_custom_phrase(raw, "diceware")
            self.assertEqual(pm.current_phrase(), result)
            self.assertEqual(pm.current_phrase().suffix, "correct horse battery staple")
            self.assertFalse(next_path.exists())
        finally:
            tmpdir.cleanup()


class TestPassphraseParse(unittest.TestCase):
    def test_parse_splits_last_n_words_as_suffix(self):
        p = Passphrase.parse("alpha bravo one two three four", suffix_word_count=4)
        self.assertEqual(p.prefix, "alpha bravo")
        self.assertEqual(p.suffix, "one two three four")

    def test_parse_rejects_a_too_long_prefix_rather_than_silently_disclosing_more(self):
        # A too-long custom entry must be rejected outright, not silently
        # treated as "extra prefix words" -- that would shrink the actual
        # secret (fewer words held back as suffix) while the owner believes
        # the phrase still has its intended 2-word-disclosed shape.
        with self.assertRaises(ValueError):
            Passphrase.parse("alpha bravo charlie one two three four", suffix_word_count=4)

    def test_full_joins_prefix_and_suffix(self):
        p = Passphrase(prefix="bravo six", suffix="going dark")
        self.assertEqual(p.full, "bravo six going dark")

    def test_repr_never_exposes_the_suffix(self):
        p = Passphrase(prefix="bravo six", suffix="going dark echo delta hotel signal breach")
        rendered = repr(p)
        self.assertIn("bravo six", rendered)
        self.assertNotIn("going dark", rendered)
        self.assertNotIn("echo", rendered)

    def test_str_also_never_exposes_the_suffix(self):
        p = Passphrase(prefix="bravo six", suffix="correct horse battery staple")
        self.assertNotIn("correct horse", str(p))


class TestStyleOf(unittest.TestCase):
    def test_diceware_suffix_length_infers_diceware(self):
        from phrase_manager import style_of
        p = Passphrase(prefix="a b", suffix="one two three four")
        self.assertEqual(style_of(p), "diceware")

    def test_tactical_suffix_length_infers_tactical(self):
        from phrase_manager import style_of
        p = Passphrase(prefix="a b", suffix="one two three four five six seven")
        self.assertEqual(style_of(p), "tactical")


class TestDecodeToleratesTrailingNewline(unittest.TestCase):
    def test_trailing_newline_does_not_break_decode(self):
        tmpdir = tempfile.TemporaryDirectory()
        try:
            phrase_path = Path(tmpdir.name) / "phrase.txt"
            next_path = Path(tmpdir.name) / "phrase.next"
            pm = PhraseManager(str(phrase_path), str(next_path))
            phrase_path.write_text("bravo six\ngoing dark echo delta hotel signal breach\n", encoding="utf-8")
            current = pm.current_phrase()
            self.assertEqual(current.prefix, "bravo six")
            self.assertEqual(current.suffix, "going dark echo delta hotel signal breach")
        finally:
            tmpdir.cleanup()


if __name__ == "__main__":
    unittest.main()
