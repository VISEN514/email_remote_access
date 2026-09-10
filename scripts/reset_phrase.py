"""Physical-access-only recovery: run this BY HAND, directly on the laptop's
own keyboard, to force-regenerate the phrase and email it to yourself.

There is deliberately no remote/network trigger anywhere in this system for
this action -- it exists specifically so it can't be invoked by an attacker.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from config import Config  # noqa: E402
from gmail_client import GmailClient  # noqa: E402
from notifier import Notifier  # noqa: E402
from phrase_manager import PhraseManager  # noqa: E402


def main():
    style = sys.argv[1] if len(sys.argv) > 1 else "diceware"
    config = Config()
    phrase_manager = PhraseManager(config.access["phrase_path"], config.access["phrase_next_path"])
    new_phrase = phrase_manager.physical_reset(style)

    gmail = GmailClient(config.gmail["credentials_path"], config.gmail["token_path"])
    notifier = Notifier(gmail, alert_to=config.notify["alert_to"])
    notifier.send_with_retry(
        subject="Remote access phrase reset",
        body=f"Your phrase was reset via physical access. New phrase:\n{new_phrase.full}",
    )
    print(f"Phrase reset and emailed. Disclosed prefix: {new_phrase.prefix!r} (kept locally in phrase.txt)")


if __name__ == "__main__":
    main()
