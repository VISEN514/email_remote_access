import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from auth_check import check_authenticated

TRUSTED = "mx.google.com"


def headers(auth_results=None, received=None):
    h = []
    if auth_results is not None:
        for v in auth_results:
            h.append({"name": "Authentication-Results", "value": v})
    if received is not None:
        for v in received:
            h.append({"name": "Received", "value": v})
    return h


class TestAuthCheck(unittest.TestCase):
    def test_missing_headers_fail_closed(self):
        self.assertFalse(check_authenticated(headers(), TRUSTED))

    def test_valid_gmail_pass(self):
        h = headers(
            auth_results=["mx.google.com; spf=pass dkim=pass dmarc=pass"],
            received=["by mx.google.com with SMTP id abc123"],
        )
        v = check_authenticated(h, TRUSTED)
        self.assertTrue(v.ok)

    def test_forged_authserv_id_rejected(self):
        h = headers(
            auth_results=["evil-relay.example; spf=pass dkim=pass dmarc=pass"],
            received=["by evil-relay.example with SMTP id abc123"],
        )
        v = check_authenticated(h, TRUSTED)
        self.assertFalse(v.ok)

    def test_attacker_appended_second_header_is_not_trusted(self):
        # First entry (Gmail's own) fails; attacker's forged second entry
        # claiming pass must NOT rescue the message -- we only trust position 0.
        h = headers(
            auth_results=[
                "mx.google.com; spf=fail dkim=fail dmarc=fail",
                "mx.google.com; spf=pass dkim=pass dmarc=pass",  # forged, ignored
            ],
            received=["by mx.google.com with SMTP id abc123"],
        )
        v = check_authenticated(h, TRUSTED)
        self.assertFalse(v.ok)

    def test_authresults_and_received_disagreement_fails_closed(self):
        h = headers(
            auth_results=["mx.google.com; spf=pass dkim=pass dmarc=pass"],
            received=["by suspicious-other-host.example with SMTP id abc123"],
        )
        v = check_authenticated(h, TRUSTED)
        self.assertFalse(v.ok)

    def test_received_by_clause_smuggling_is_not_fooled_by_substring(self):
        # An attacker-controlled HELO string / comment containing a Google
        # substring elsewhere in the Received line must NOT satisfy the
        # cross-check -- only the actual "by <host>" clause counts.
        h = headers(
            auth_results=["mx.google.com; spf=pass dkim=pass dmarc=pass"],
            received=["from attacker-relay.example (helo=google.com-totally-legit) by evil.example with SMTP"],
        )
        v = check_authenticated(h, TRUSTED)
        self.assertFalse(v.ok)

    def test_partial_pass_rejected(self):
        h = headers(
            auth_results=["mx.google.com; spf=pass dkim=fail dmarc=pass"],
            received=["by mx.google.com with SMTP id abc123"],
        )
        v = check_authenticated(h, TRUSTED)
        self.assertFalse(v.ok)


if __name__ == "__main__":
    unittest.main()
