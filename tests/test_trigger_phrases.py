import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import unittest

from trigger_phrases import classify_trigger


class TestClassifyTrigger(unittest.TestCase):
    def test_recognized_login_trigger(self):
        self.assertEqual(classify_trigger("tap me in"), "login")
        self.assertEqual(classify_trigger("log me in"), "login")

    def test_recognized_rotate_trigger(self):
        self.assertEqual(classify_trigger("rotate phrase"), "rotate")

    def test_unrecognized_text_returns_none(self):
        self.assertIsNone(classify_trigger("hello there"))

    def test_case_sensitivity_handled_by_caller_normalization(self):
        # classify_trigger expects an already-normalized (casefolded) line --
        # mail_watcher._first_nonblank_line is what normalizes before calling.
        self.assertIsNone(classify_trigger("Tap Me In"))


if __name__ == "__main__":
    unittest.main()
