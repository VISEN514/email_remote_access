# Email-triggered remote access

Implements [PLAN.md](PLAN.md) (v2, two-step challenge/response, reviewed to
9.7/10). Email a trigger phrase, get back half of today's verification
phrase, reply with the rest, get back a one-time browser link with full
remote control of this laptop.

## Architecture, in brief
- `src/main.py` -- the watcher/broker process, runs as the interactive owning
  Windows user (not LocalSystem), wrapped as a service via NSSM.
- `src/mail_watcher.py` + `src/auth_check.py` -- polls Gmail, trusts only the
  Authentication-Results/Received entries Gmail's own MTA appended (fails
  closed on anything ambiguous), applies the allow-list, and runs the
  two-step challenge/response state machine (`src/challenge_store.py`,
  `src/trigger_phrases.py`, `src/reply_matching.py`).
- `src/phrase_manager.py` + `src/wordlists.py` -- daily human-readable
  passphrase (2-word disclosed prefix + a per-style undisclosed suffix
  sized to a ~40+ bit floor), crash-safe rotation: stage, attempt session
  start, commit (rename) BEFORE notifying, never after.
- `src/popup_app.py` -- the local Tkinter/customtkinter popup for setting or
  generating the daily phrase (see "Fonts" below); `scripts/register_popup_task.ps1`
  wires it into Task Scheduler for a fixed daily time.
- `src/session_broker.py` + `src/bridge_entrypoint.py` + `src/vnc_bridge_app.py`
  -- one bridge subprocess per session, PID-reuse-safe crash/restart
  reconciliation, nonce-in-URL/real-token-in-cookie split, dual expiry.
- `src/tunnel/` -- swappable provider; Cloudflare quick tunnel implemented,
  Tailscale Funnel stubbed.
- `src/security_level_store.py` -- runtime-selectable security level (see
  "Security levels" below), set via the popup, read fresh each poll cycle.
- TightVNC itself is a separate, persistent Windows service (installed by
  its own installer, runs as `LocalSystem` for lock-screen/SAS access) that
  this codebase never starts or stops -- only the bridge in front of it.

## One-time setup

### 1. TightVNC
Install from tightvnc.com as its own Windows service, loopback-bound
(`127.0.0.1:5900`), strong password, pinned version, clipboard/file-transfer
disabled in its settings. Confirm whether its service mode supports an
external config path for the password:
- if yes: move it into `secrets/` as its own file, with a `SYSTEM` read ACL
  on that file only (never at the `secrets/` folder level)
- if no: tighten `HKLM\SOFTWARE\TightVNC\Server`'s ACL to `SYSTEM`
  (read/write) + your interactive account (read), all other accounts removed

Configure the TightVNC service's own Recovery actions (Services MMC ->
TightVNC Server -> Recovery) for restart-on-failure -- this is separate from
NSSM, which only wraps the watcher/broker below.

### 2. cloudflared
Download from https://github.com/cloudflare/cloudflared/releases/latest,
put on PATH (or set `tunnel.cloudflared_path` in `config.yaml`).

### 3. noVNC
```powershell
git clone https://github.com/novnc/noVNC "C:\Users\vihaa\Projects\email-remote-access\novnc"
```

### 4. Dedicated Gmail account + OAuth credentials
Create a new Gmail account for this service. In Google Cloud Console:
enable the Gmail API, create a Desktop-app OAuth client, save the JSON as
`secrets\credentials.json`.

### 5. Python environment
```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

### 6. Configure
```powershell
copy config.example.yaml config.yaml
```
Set `access.allowed_senders` and `notify.alert_to` to your personal address(es).

### 7. Authorize Gmail (one-time interactive)
```powershell
.venv\Scripts\python scripts\authorize_gmail.py
```
Sign in as the dedicated watcher account.

### 8. Install the popup's fonts (optional, cosmetic only)
```powershell
.\scripts\install_fonts.ps1
```
Installs the bundled tactical-theme fonts (`assets/fonts/`, all free/OFL).
The popup falls back to a plain monospace theme if skipped -- purely visual,
not required for the system to work.

### 9. Register the daily phrase popup
```powershell
.\scripts\register_popup_task.ps1
```
Registers a Task Scheduler entry that pops up `src\popup_app.py` daily at
6am (configurable in the script) to set/generate that day's phrase. Run it
manually anytime with `.venv\Scripts\python src\popup_app.py`. The initial
phrase (if you never run the popup first) is auto-generated into
`secrets\phrase.txt` on `main.py`'s first run.

### 10. Test in the foreground
```powershell
.venv\Scripts\python src\main.py
```
From an allowed sender, email one of the trigger phrases (PLAN.md section
1, e.g. "tap me in"); the watcher replies with the disclosed 2-word prefix
(check `secrets\phrase.txt` locally, or the popup, if you need the full
phrase). Reply with the rest to get the session link.

### 11. Install as a service
```powershell
.\service\install_service.ps1
```
Then in `nssm edit EmailRemoteAccessWatcher`, set the service to log on as
your own interactive account (Log On tab) -- not LocalSystem.

### 12. Power settings
Disable sleep on AC power; the system needs the laptop awake to be reachable
(Phase 2/Wake-on-LAN deferred, see PLAN.md).

## Recovery
If you ever lose track of the current phrase, run, by hand, on the laptop
(or use the popup's "Generate Random Phrase" button):
```powershell
.venv\Scripts\python scripts\reset_phrase.py [diceware|tactical]
```
This has no remote trigger anywhere in the system by design.

If a sender's pending challenge slot gets stuck (PLAN.md section 5's named
DoS residual -- someone retriggering just under the 5-minute expiry), clear
it locally: open the popup and click "Clear Stuck Pending Challenge." Also
physical-access-only by design.

## Security levels
Selectable from the popup, takes effect on the watcher's next poll cycle
(no restart needed):
- **Level 2 (default)**: today's system -- authenticated AND allow-listed
  sender required. Nothing changes from the base flow above.
- **Level 1**: drops the allow-list check -- any authenticated sender who
  knows the phrase can complete a login. This is a genuine, deliberate
  authentication-model downgrade (secret-only instead of identity+secret),
  not a minor variant -- see PLAN.md's "Real security delta" section before
  using it. A rolling 1-hour cap (`access.l1_max_new_senders_per_hour`,
  default 15) on distinct never-before-seen senders bounds the
  volumetric/flood exposure this opens up; your own allow-listed address is
  always exempt from that cap. Entering Level 1 always emails an alert, and
  the heartbeat flags it as degraded if it's been active continuously for
  more than `access.l1_max_continuous_hours` (default 24) -- detection
  only, it won't auto-revert for you.
- **Level 3** (passphrase + allow-list + a physical FIDO2/WebAuthn key) is
  designed but deferred -- see PLAN.md's "Deferred: Level 3" section. It
  needs a small fixed-domain service for the WebAuthn ceremony (not a
  switch away from the random-hostname tunnel entirely); revisit if/when
  you're open to standing up a small fixed domain for just that.

## Tests
```powershell
.venv\Scripts\python -m unittest discover -s tests
```
