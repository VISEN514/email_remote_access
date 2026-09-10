"""One-time interactive Gmail OAuth setup for the watcher account. Run by
hand, logged into the DEDICATED watcher Gmail account, after placing the
OAuth client secret at secrets/credentials.json."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from google_auth_oauthlib.flow import InstalledAppFlow  # noqa: E402
from gmail_client import SCOPES  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CREDENTIALS_PATH = ROOT / "secrets" / "credentials.json"
TOKEN_PATH = ROOT / "secrets" / "token.json"


def main():
    if not CREDENTIALS_PATH.exists():
        raise SystemExit(f"Missing {CREDENTIALS_PATH}. Download the OAuth client secret first.")
    flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_PATH), SCOPES)
    creds = flow.run_local_server(port=0)
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_PATH.write_text(creds.to_json(), encoding="utf-8")
    print(f"Wrote {TOKEN_PATH}.")


if __name__ == "__main__":
    main()
