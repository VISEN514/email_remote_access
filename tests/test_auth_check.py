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

    def test_real_gmail_delivery_with_internal_gfe_hop_above_mx_google_com(self):
        # Regression test for a real field-testing bug: genuine Gmail-to-Gmail
        # delivery appends an INNERMOST internal-delivery Received header
        # (Gmail frontend -> mailbox, "by <internal id> with SMTP id ...")
        # ABOVE the "by mx.google.com" hop this check cares about -- so
        # position 0 is that internal hop, not "by mx.google.com". An
        # earlier version of this check only looked at position 0 and
        # rejected every real Gmail message because of this. Headers below
        # are trimmed from an actual captured message.
        h = headers(
            auth_results=[
                "mx.google.com; dkim=pass header.i=@gmail.com header.s=20251104 "
                "header.b=CyzBAaoo; spf=pass smtp.mailfrom=av.oct15@gmail.com; "
                "dmarc=pass header.from=gmail.com"
            ],
            received=[
                "by 2002:ad4:4707:0:b0:910:4b0f:dc3f with SMTP id qb7csp1150933qvb;"
                "        Sun, 13 Sep 2026 10:50:32 -0700 (PDT)",
                "from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])"
                "        by mx.google.com with SMTPS id a640c23a62f3a-c2965b3caf9sor192400066b.1"
                "        for <poietics.relay@gmail.com>        (Google Transport Security);"
                "        Sun, 13 Sep 2026 10:50:31 -0700 (PDT)",
            ],
        )
        v = check_authenticated(h, TRUSTED)
        self.assertTrue(v.ok, v.reason)

    def test_received_trust_search_does_not_go_past_bounded_depth(self):
        # The search is bounded to the top 2 entries, not unbounded -- a
        # trusted "by mx.google.com" hop sitting at position 2 or deeper
        # must NOT be found, preserving the original fail-closed guarantee
        # (an attacker-forged Received header sits further down the stack).
        h = headers(
            auth_results=["mx.google.com; spf=pass dkim=pass dmarc=pass"],
            received=[
                "by untrusted-hop-one.example with SMTP id aaa",
                "by untrusted-hop-two.example with SMTP id bbb",
                "by mx.google.com with SMTP id ccc",  # too deep, must not count
            ],
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
