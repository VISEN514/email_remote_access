import logging
import time

from gmail_client import GmailClient

logger = logging.getLogger("notifier")


class Notifier:
    def __init__(self, gmail: GmailClient, alert_to: str):
        self.gmail = gmail
        self.alert_to = alert_to

    def send_with_retry(self, subject: str, body: str, attempts: int = 5, backoff_seconds: float = 10.0) -> bool:
        for attempt in range(1, attempts + 1):
            try:
                self.gmail.send(to=self.alert_to, subject=subject, body=body)
                return True
            except Exception:
                logger.exception("Send attempt %s/%s failed", attempt, attempts)
                if attempt < attempts:
                    time.sleep(backoff_seconds)
        return False

    # -- challenge/response (PLAN.md section 5) -----------------------------
    def send_challenge_prefix(self, prefix: str):
        """Step 3: emails back ONLY the disclosed prefix -- the suffix is
        never sent anywhere by this system."""
        return self.send_with_retry(
            subject="Verification -- reply with the rest",
            body=(
                f"{prefix}\n\n"
                "Reply with the rest of today's phrase to continue. "
                "This request expires in 5 minutes."
            ),
        )

    def send_wrong_suffix_alert(self, sender: str, lockout_minutes: int, locked: bool):
        if locked:
            self.send_lockout_alert(sender, lockout_minutes)
            return
        self.send_with_retry(
            subject="Verification failed",
            body="That didn't match. Try again, or send a trigger phrase to start over.",
            attempts=1,
        )

    def send_session_link(self, url: str, absolute_timeout_minutes: int) -> bool:
        # No phrase rotation happens on login in v2 (PLAN.md section 3) --
        # this no longer includes a next phrase, unlike v1.
        return self.send_with_retry(
            subject="Your remote access link is ready",
            body=(
                f"{url}\n\n"
                f"This link expires after {absolute_timeout_minutes} minutes or on idle timeout, "
                "and can only be used once to establish a session."
            ),
        )

    def send_session_start_failed(self):
        self.send_with_retry(
            subject="Remote access request succeeded, but the session failed to start",
            body=(
                "Your request was verified, but the session (VNC/tunnel) failed to start. "
                "Send the trigger phrase again to retry."
            ),
        )

    # -- rotation (PLAN.md section 6) ---------------------------------------
    def send_rotated_phrase(self, phrase_full: str):
        return self.send_with_retry(
            subject="New verification phrase",
            body=f"Your new verification phrase is:\n{phrase_full}\n\nThe old phrase no longer works.",
        )

    def send_rotation_on_cooldown(self):
        self.send_with_retry(
            subject="Rotation not applied -- on cooldown",
            body=(
                "You confirmed the current phrase correctly, but a rotation happened too "
                "recently (minimum 10 minutes between rotations). The current phrase is "
                "still active; try again shortly if you still want a new one."
            ),
            attempts=1,
        )

    def send_phrase_rotation_failed(self):
        self.send_with_retry(
            subject="Rotation failed",
            body="Your phrase was confirmed but generating/writing the new one failed. The old phrase is still active.",
            attempts=1,
        )

    # -- security level (PLAN.md "Selectable security levels") -------------
    def send_security_level_alert(self, new_level: int):
        self.send_with_retry(
            subject="Remote access: security level changed",
            body=(
                f"Security level is now {new_level}. "
                + (
                    "Level 1 drops the sender allow-list check -- any authenticated "
                    "sender who knows the phrase can attempt access. Change it back "
                    "from the local popup if this wasn't intentional or isn't still needed."
                    if new_level == 1
                    else "Level 2 (default): authenticated AND allow-listed sender required."
                )
            ),
            attempts=1,
        )

    # -- logout (PLAN.md section 8) ------------------------------------------
    def send_logout_confirmation(self, clean: bool):
        if clean:
            self.send_with_retry(
                subject="Session ended",
                body="Your remote access session was ended and torn down cleanly.",
                attempts=1,
            )
        else:
            self.send_with_retry(
                subject="Session ended (partial teardown)",
                body=(
                    "Your remote access session was ended, but teardown was only PARTIALLY "
                    "clean -- check the laptop and logs if you have physical access soon."
                ),
                attempts=1,
            )

    # -- flood/heartbeat (PLAN.md section 7) ---------------------------------
    def send_abandoned_flood_alert(self, sender: str):
        self.send_with_retry(
            subject="Remote access: repeated unanswered challenges",
            body=(
                f"{sender} triggered 10+ challenges within an hour without ever replying to "
                "complete one. This may be normal distracted use, or someone probing -- "
                "check in if you didn't do this yourself."
            ),
            attempts=1,
        )

    def send_lockout_alert(self, sender: str, lockout_minutes: int):
        self.send_with_retry(
            subject="Remote access: repeated failed attempts",
            body=(
                f"{sender} failed verification enough times to trigger a "
                f"{lockout_minutes}-minute lockout."
            ),
        )
