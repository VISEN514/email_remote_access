import base64
from email.mime.text import MIMEText
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# PLAN.md: gmail.modify (not gmail.readonly) is required -- the watcher needs
# to remove UNREAD and apply the flood-defense archive/trash label actions,
# both write operations gmail.readonly cannot perform. Still excludes
# messages.delete (permanent deletion requires the much broader
# https://mail.google.com/ scope, deliberately not requested).
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]


class GmailClient:
    def __init__(self, credentials_path: str, token_path: str):
        self.credentials_path = Path(credentials_path)
        self.token_path = Path(token_path)
        self._service = None

    def _load_credentials(self) -> Credentials:
        if not self.token_path.exists():
            raise RuntimeError(
                f"No token at {self.token_path}. Run scripts/authorize_gmail.py once interactively."
            )
        creds = Credentials.from_authorized_user_file(str(self.token_path), SCOPES)
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
                self.token_path.write_text(creds.to_json(), encoding="utf-8")
            else:
                raise RuntimeError(
                    f"Token at {self.token_path} is invalid and has no refresh token. "
                    "Re-run scripts/authorize_gmail.py."
                )
        return creds

    @property
    def service(self):
        if self._service is None:
            self._service = build("gmail", "v1", credentials=self._load_credentials())
        return self._service

    def list_unread_ids(self) -> list[str]:
        """Paginates through ALL unread messages, not just the first page --
        a sustained flood exceeding one page (Gmail's default page size is
        100) would otherwise leave excess messages unprocessed/unarchived
        each cycle, understating the flood-defense threshold and letting the
        mailbox grow unbounded."""
        ids: list[str] = []
        page_token = None
        while True:
            resp = (
                self.service.users()
                .messages()
                .list(userId="me", labelIds=["INBOX", "UNREAD"], pageToken=page_token)
                .execute()
            )
            ids.extend(m["id"] for m in resp.get("messages", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        return ids

    def get_headers(self, msg_id: str) -> list[dict]:
        """Fetch only headers -- cheap, and enough for both the flood-triage
        threshold check and the Authentication-Results/Received cross-check,
        which both need the same header set (PLAN.md flood-defense section)."""
        msg = (
            self.service.users()
            .messages()
            .get(
                userId="me",
                id=msg_id,
                format="metadata",
                metadataHeaders=["Authentication-Results", "From", "Received"],
            )
            .execute()
        )
        return msg["payload"]["headers"]

    def get_body_text(self, msg_id: str) -> str:
        msg = self.service.users().messages().get(userId="me", id=msg_id, format="full").execute()
        return _extract_body(msg["payload"])

    def mark_read(self, msg_id: str):
        self.service.users().messages().modify(
            userId="me", id=msg_id, body={"removeLabelIds": ["UNREAD"]}
        ).execute()

    def batch_mark_read(self, msg_ids: list[str]):
        if not msg_ids:
            return
        self.service.users().messages().batchModify(
            userId="me", body={"ids": msg_ids, "removeLabelIds": ["UNREAD"]}
        ).execute()

    def archive(self, msg_id: str):
        self.service.users().messages().modify(
            userId="me", id=msg_id, body={"removeLabelIds": ["INBOX"]}
        ).execute()

    def trash(self, msg_id: str):
        self.service.users().messages().trash(userId="me", id=msg_id).execute()

    def batch_archive(self, msg_ids: list[str], trash_instead: bool = False):
        if not msg_ids:
            return
        if trash_instead:
            for msg_id in msg_ids:
                self.trash(msg_id)
            return
        self.service.users().messages().batchModify(
            userId="me", body={"ids": msg_ids, "removeLabelIds": ["INBOX"]}
        ).execute()

    def send(self, to: str, subject: str, body: str):
        message = MIMEText(body)
        message["to"] = to
        message["subject"] = subject
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        self.service.users().messages().send(userId="me", body={"raw": raw}).execute()


def _extract_body(payload) -> str:
    if payload.get("body", {}).get("data"):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="ignore")
    for part in payload.get("parts", []) or []:
        text = _extract_body(part)
        if text:
            return text
    return ""
