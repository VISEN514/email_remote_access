import logging
import time

from challenge_store import ChallengeStore
from config import Config
from gmail_client import GmailClient
from heartbeat import Heartbeat
from lockout import LockoutTracker
from mail_watcher import MailWatcher
from notifier import Notifier
from phrase_manager import PhraseManager
from security_level_store import SecurityLevelStore
from session_broker import SessionBroker
from state_store import StateStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("main")


def build_on_valid_request(broker: SessionBroker, notifier: Notifier, config: Config):
    """Handles all three outcomes of a LOGIN challenge (PLAN.md section 5):
    challenge issued (challenge_prefix set), suffix mismatch (valid=False),
    suffix match (valid=True). No phrase rotation happens here in v2 --
    rotation is scheduled/on-demand/remote-confirmed only (PLAN.md section 3)."""
    def on_valid_request(sender: str, valid, just_locked: bool, challenge_prefix):
        if challenge_prefix is not None:
            notifier.send_challenge_prefix(challenge_prefix)
            return

        if just_locked:
            notifier.send_lockout_alert(sender, config.access["lockout_minutes"])
            return

        if not valid:
            notifier.send_wrong_suffix_alert(sender, config.access["lockout_minutes"], locked=False)
            return

        try:
            url = broker.start_session()
        except Exception:
            logger.exception("Session failed to start for %s", sender)
            notifier.send_session_start_failed()
            return

        delivered = notifier.send_session_link(url, config.session["absolute_timeout_minutes"])
        if not delivered:
            logger.error(
                "SESSION STARTED BUT NOTIFICATION DELIVERY UNCONFIRMED for %s -- "
                "session is live, owner may not know the link yet",
                sender,
            )

    return on_valid_request


def build_on_rotation(phrase_manager: PhraseManager, challenges: ChallengeStore, notifier: Notifier, config: Config):
    """PLAN.md section 6: fired only after a rotate-confirmation challenge's
    suffix reply has already been verified to match (mail_watcher/
    challenge_store own that check) -- this only still needs to enforce the
    10-minute cooldown between successful rotations before actually
    generating and emailing a new phrase."""
    def on_rotation(sender: str, style: str):
        if challenges.rotation_on_cooldown(sender):
            logger.info("Rotate-confirmation from %s matched, but rotation is on cooldown", sender)
            notifier.send_rotation_on_cooldown()
            return

        try:
            new_phrase = phrase_manager.remote_rotate(style)
        except Exception:
            logger.exception("Remote rotation failed for %s", sender)
            notifier.send_phrase_rotation_failed()
            return

        challenges.record_rotation_success(sender)
        delivered = notifier.send_rotated_phrase(new_phrase.full)
        if not delivered:
            logger.error(
                "PHRASE ROTATED BUT NOTIFICATION DELIVERY UNCONFIRMED for %s -- "
                "new phrase is live, owner may not know it yet",
                sender,
            )

    return on_rotation


def build_on_abandoned_flood(notifier: Notifier):
    def on_abandoned_flood(sender: str):
        notifier.send_abandoned_flood_alert(sender)

    return on_abandoned_flood


def build_on_session_end(notifier: Notifier):
    def on_session_end(clean: bool):
        notifier.send_logout_confirmation(clean=clean)

    return on_session_end


def main():
    config = Config()

    gmail = GmailClient(config.gmail["credentials_path"], config.gmail["token_path"])
    notifier = Notifier(gmail, alert_to=config.notify["alert_to"])
    # ONE StateStore instance for the whole process, shared by everything
    # that touches config.session["state_path"] -- a StateStore's atomicity
    # comes from an in-process lock, which only protects callers holding
    # this exact instance. Constructing a second StateStore elsewhere
    # pointed at the same file would have its own, different lock and
    # provide zero protection against concurrent writes from this one.
    state_store = StateStore(config.session["state_path"])
    notifier_for_broker = notifier
    broker = SessionBroker(
        config.session,
        config.tunnel,
        state=state_store,
        on_session_end=build_on_session_end(notifier_for_broker),
    )
    phrase_manager = PhraseManager(config.access["phrase_path"], config.access["phrase_next_path"])
    lockout = LockoutTracker(
        state_store,
        max_failed_attempts=config.access["max_failed_attempts"],
        lockout_minutes=config.access["lockout_minutes"],
    )
    challenges = ChallengeStore(state_store)
    security_level_store = SecurityLevelStore(
        state_store,
        allowed_senders=config.access["allowed_senders"],
        max_new_senders_per_hour=config.access.get("l1_max_new_senders_per_hour", 15),
        default_level=config.access["default_security_level"],
    )
    heartbeat = Heartbeat(
        vnc_host=config.session["vnc_host"],
        vnc_port=config.session["vnc_port"],
        phrase_path=config.access["phrase_path"],
        security_level_store=security_level_store,
        l1_max_continuous_hours=config.access.get("l1_max_continuous_hours", 24),
        external_ping_url=config.heartbeat.get("external_ping_url", ""),
    )

    watcher = MailWatcher(
        gmail=gmail,
        access_config=config.access,
        flood_config=config.flood,
        trusted_authserv_id=config.gmail["trusted_authserv_id"],
        lockout=lockout,
        phrase_manager=phrase_manager,
        challenges=challenges,
        security_level_store=security_level_store,
        on_valid_request=build_on_valid_request(broker, notifier, config),
        on_rotation=build_on_rotation(phrase_manager, challenges, notifier, config),
        on_abandoned_flood=build_on_abandoned_flood(notifier),
        handled_ids_store=state_store,
    )

    poll_interval = config.gmail["poll_interval_seconds"]
    logger.info("Mail watcher started, polling every %ss", poll_interval)
    while True:
        ok = watcher.poll_once()
        heartbeat.report_cycle(ok)
        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
