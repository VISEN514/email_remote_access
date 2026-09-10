import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import unittest

from reply_matching import reply_matches_suffix


class TestReplyMatching(unittest.TestCase):
    def test_exact_whole_body_match(self):
        self.assertTrue(reply_matches_suffix("going dark echo delta hotel signal breach", "going dark echo delta hotel signal breach"))

    def test_case_and_whitespace_insensitive(self):
        self.assertTrue(reply_matches_suffix("  Going   Dark\nEcho Delta Hotel Signal Breach  ", "going dark echo delta hotel signal breach"))

    def test_quoted_reply_gt_prefix_stripped(self):
        body = "correct horse battery staple\n> original trigger message\n> was here"
        self.assertTrue(reply_matches_suffix(body, "correct horse battery staple"))

    def test_top_posting_with_on_wrote_marker(self):
        body = "correct horse battery staple\n\nOn Mon, Jan 1, 2026 at 9:00 AM Owner <owner@example.com> wrote:\n> tap me in"
        self.assertTrue(reply_matches_suffix(body, "correct horse battery staple"))

    def test_signature_dash_marker(self):
        body = "correct horse battery staple\n--\nSent from my iPhone"
        self.assertTrue(reply_matches_suffix(body, "correct horse battery staple"))

    def test_bottom_posting_is_an_explicitly_out_of_scope_case(self):
        # PLAN.md section 5 explicitly scopes this to Gmail/Outlook/Apple
        # Mail's default TOP-posting behavior, not claimed universal -- a
        # genuinely bottom-posting client (suffix typed BELOW the quote
        # marker) is named as out of scope, not silently promised to work.
        # This test documents that limit rather than asserting it's fixed.
        body = "On Mon, Jan 1, 2026 at 9:00 AM Owner <owner@example.com> wrote:\n> tap me in\ncorrect horse battery staple"
        self.assertFalse(reply_matches_suffix(body, "correct horse battery staple"))

    def test_mismatch_is_rejected(self):
        self.assertFalse(reply_matches_suffix("wrong words entirely here", "correct horse battery staple"))

    def test_partial_suffix_is_not_a_match(self):
        # Guards against a substring-search regression (rev2's actual bug):
        # a body containing only part of the suffix must not match.
        self.assertFalse(reply_matches_suffix("correct horse", "correct horse battery staple"))

    def test_suffix_embedded_in_longer_unrelated_text_does_not_match(self):
        body = "correct horse battery staple extra unrelated words after it"
        self.assertFalse(reply_matches_suffix(body, "correct horse battery staple"))


if __name__ == "__main__":
    unittest.main()
