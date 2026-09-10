"""Local desktop popup (PLAN.md section 4). Runs interactively as the
logged-in owning user (Task Scheduler "run only when user is logged on") --
same trust boundary as scripts/reset_phrase.py: this only does anything if
someone is actually logged into the laptop.

Offers:
  - Generate Random (style toggle: tactical/NATO or plain diceware)
  - Type a custom phrase (normalized before being written)
  - Clear stuck pending challenge (physical-access-only DoS recovery,
    PLAN.md section 5)

Built with customtkinter (a themed layer over Tk) rather than plain Tkinter
purely for appearance -- every action below calls the exact same
PhraseManager/ChallengeStore/Notifier methods a plain-Tk version would.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import customtkinter as ctk  # noqa: E402
from tkinter import font as tkfont, messagebox  # noqa: E402

from challenge_store import ChallengeStore  # noqa: E402
from config import Config  # noqa: E402
from gmail_client import GmailClient  # noqa: E402
from notifier import Notifier  # noqa: E402
from phrase_manager import PhraseManager, STYLES  # noqa: E402
from security_level_store import SecurityLevelStore  # noqa: E402
from state_store import StateStore  # noqa: E402

# -- fixed dark/tactical theme, not "system" -- rendering blur on a mixed
# light/dark or fractionally-scaled system theme is what made the previous
# version look soft; forcing a single theme + explicit widget/window
# scaling keeps every widget rendering at a crisp, predictable pixel grid
# regardless of the host display's DPI settings.
ctk.set_appearance_mode("dark")
ctk.set_widget_scaling(1.0)
ctk.set_window_scaling(1.0)

# -- palette: black / white / sage green, no other hues --------------------
_BLACK = "#0A0B09"
_PANEL = "#14160F"
_PANEL_BORDER = "#2A2E20"
_WHITE = "#F2F3EE"
_DIM = "#8C9080"
_SAGE = "#8FA37A"
_SAGE_DIM = "#6F8060"
_SAGE_HOVER = "#7C9166"
_DANGER = "#B7472A"
_DANGER_HOVER = "#943A22"

_MONO = "Consolas"

# Header/subhead/body use three free, open-license (SIL OFL) Google Fonts
# chosen for the tactical/HUD look, if the machine running this popup has
# them installed: Black Ops One (stencil/military header), Chakra Petch (a
# technical HUD-style display face for the subhead), and Titillium Web (a
# clean aviation/sci-fi-HUD body face, used in real dashboard-style UIs).
# _available_font() checks Tk's actual installed-family list at runtime and
# falls back to the existing Consolas-based tactical theme per-role if a
# given font isn't present, so the popup still looks intentional (not
# broken/mismatched) on a machine that doesn't have them installed.
_FONT_HEADER = "Black Ops One"
_FONT_SUBHEAD = "Chakra Petch"
_FONT_BODY = "Titillium Web"


def _available_font(preferred: str, fallback: str) -> str:
    try:
        installed = {f.lower() for f in tkfont.families()}
    except Exception:
        return fallback
    return preferred if preferred.lower() in installed else fallback


class PopupApp:
    def __init__(self, root: ctk.CTk, config: Config):
        self.root = root
        self.config = config
        self.phrase_manager = PhraseManager(config.access["phrase_path"], config.access["phrase_next_path"])
        self.state_store = StateStore(config.session["state_path"])
        self.challenges = ChallengeStore(self.state_store)
        self.gmail = GmailClient(config.gmail["credentials_path"], config.gmail["token_path"])
        self.notifier = Notifier(self.gmail, alert_to=config.notify["alert_to"])
        self.security_level_store = SecurityLevelStore(
            self.state_store,
            allowed_senders=config.access["allowed_senders"],
            max_new_senders_per_hour=config.access.get("l1_max_new_senders_per_hour", 15),
            default_level=config.access["default_security_level"],
        )

        root.title("REMOTE ACCESS")
        root.geometry("460x720")
        root.resizable(False, False)
        root.configure(fg_color=_BLACK)

        # Resolved once the Tk root exists (tkfont.families() needs a live
        # Tk instance) -- each falls back independently to the tactical
        # mono theme if that specific font isn't installed on this machine.
        self.font_header = _available_font(_FONT_HEADER, _MONO)
        self.font_subhead = _available_font(_FONT_SUBHEAD, _MONO)
        self.font_body = _available_font(_FONT_BODY, _MONO)

        self.style_var = ctk.StringVar(value=config.access.get("default_phrase_style", "diceware"))

        outer = ctk.CTkFrame(root, fg_color="transparent")
        outer.pack(fill="both", expand=True, padx=22, pady=22)

        # -- header: callsign-block style ------------------------------------
        header = ctk.CTkFrame(outer, fg_color="transparent")
        header.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(
            header,
            text="R E M O T E   A C C E S S",
            font=ctk.CTkFont(family=self.font_header, size=20, weight="bold"),
            text_color=_WHITE,
        ).pack(anchor="w")
        ctk.CTkLabel(
            header,
            text="DAILY VERIFICATION PHRASE",
            font=ctk.CTkFont(family=self.font_subhead, size=12),
            text_color=_SAGE,
        ).pack(anchor="w", pady=(2, 0))
        self._rule(outer, pady=(12, 16))

        # -- current prefix panel -------------------------------------------
        prefix_card = ctk.CTkFrame(
            outer, corner_radius=2, fg_color=_PANEL, border_width=1, border_color=_PANEL_BORDER
        )
        prefix_card.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(
            prefix_card,
            text="DISCLOSED PREFIX",
            font=ctk.CTkFont(family=self.font_subhead, size=11, weight="bold"),
            text_color=_DIM,
        ).pack(anchor="w", padx=16, pady=(14, 0))
        self.prefix_label = ctk.CTkLabel(
            prefix_card,
            text=self.phrase_manager.current_phrase().prefix.upper(),
            font=ctk.CTkFont(family=self.font_header, size=24, weight="bold"),
            text_color=_SAGE,
        )
        self.prefix_label.pack(anchor="w", padx=16, pady=(2, 14))

        # -- style toggle ------------------------------------------------
        ctk.CTkLabel(
            outer, text="STYLE", font=ctk.CTkFont(family=self.font_subhead, size=12, weight="bold"), text_color=_DIM
        ).pack(anchor="w", pady=(0, 6))
        style_row = ctk.CTkSegmentedButton(
            outer,
            values=[s.upper() for s in STYLES],
            variable=self._style_display_var(),
            corner_radius=2,
            font=ctk.CTkFont(family=self.font_body, size=12, weight="bold"),
            fg_color=_PANEL,
            unselected_color=_PANEL,
            unselected_hover_color=_PANEL_BORDER,
            selected_color=_SAGE_DIM,
            selected_hover_color=_SAGE_HOVER,
            text_color=_WHITE,
            border_width=1,
        )
        style_row.pack(fill="x", pady=(0, 20))
        self._style_row = style_row

        # -- security level toggle (PLAN.md "Selectable security levels") ---
        ctk.CTkLabel(
            outer,
            text="SECURITY LEVEL",
            font=ctk.CTkFont(family=self.font_subhead, size=12, weight="bold"),
            text_color=_DIM,
        ).pack(anchor="w", pady=(0, 6))
        level_row = ctk.CTkSegmentedButton(
            outer,
            values=["LEVEL 1", "LEVEL 2"],
            variable=self._level_display_var(),
            corner_radius=2,
            font=ctk.CTkFont(family=self.font_body, size=12, weight="bold"),
            fg_color=_PANEL,
            unselected_color=_PANEL,
            unselected_hover_color=_PANEL_BORDER,
            selected_color=_DANGER,
            selected_hover_color=_DANGER_HOVER,
            text_color=_WHITE,
            border_width=1,
            command=self._on_level_change,
        )
        level_row.pack(fill="x", pady=(0, 4))
        # Allow-list display, with an explicit L1-active indicator right
        # next to it -- at Level 1 this list is NOT enforced for granting
        # access (that's the whole point of Level 1); showing it unqualified
        # would be misleading while L1 is active.
        self.allow_list_label = ctk.CTkLabel(
            outer,
            text="",
            font=ctk.CTkFont(family=self.font_body, size=10),
            text_color=_DIM,
            wraplength=400,
            justify="left",
        )
        self.allow_list_label.pack(anchor="w", pady=(0, 20))
        self._refresh_allow_list_label()

        # -- generate random --------------------------------------------------
        ctk.CTkButton(
            outer,
            text="GENERATE RANDOM PHRASE",
            height=42,
            corner_radius=2,
            fg_color=_SAGE_DIM,
            hover_color=_SAGE_HOVER,
            text_color=_BLACK,
            font=ctk.CTkFont(family=self.font_body, size=13, weight="bold"),
            command=self._on_generate,
        ).pack(fill="x", pady=(0, 20))

        self._rule(outer, pady=(0, 16))

        # -- custom phrase ---------------------------------------------------
        ctk.CTkLabel(
            outer, text="CUSTOM PHRASE", font=ctk.CTkFont(family=self.font_subhead, size=12, weight="bold"), text_color=_DIM
        ).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(
            outer,
            text="2 prefix words, then the suffix",
            font=ctk.CTkFont(family=self.font_body, size=11),
            text_color=_DIM,
        ).pack(anchor="w", pady=(0, 8))
        self.custom_entry = ctk.CTkEntry(
            outer,
            placeholder_text="bravo six going dark ...",
            height=38,
            corner_radius=2,
            fg_color=_PANEL,
            border_color=_PANEL_BORDER,
            border_width=1,
            text_color=_WHITE,
            font=ctk.CTkFont(family=self.font_body, size=13),
        )
        self.custom_entry.pack(fill="x", pady=(0, 8))
        ctk.CTkButton(
            outer,
            text="SET CUSTOM PHRASE",
            height=38,
            corner_radius=2,
            fg_color="transparent",
            border_width=1,
            border_color=_SAGE,
            text_color=_SAGE,
            hover_color=_PANEL,
            font=ctk.CTkFont(family=self.font_body, size=12, weight="bold"),
            command=self._on_custom,
        ).pack(fill="x", pady=(0, 20))

        self._rule(outer, pady=(0, 16))

        # -- danger zone -----------------------------------------------------
        ctk.CTkButton(
            outer,
            text="CLEAR STUCK PENDING CHALLENGE",
            height=38,
            corner_radius=2,
            fg_color=_DANGER,
            hover_color=_DANGER_HOVER,
            text_color=_WHITE,
            font=ctk.CTkFont(family=self.font_body, size=12, weight="bold"),
            command=self._on_clear_pending,
        ).pack(fill="x", pady=(4, 0))

        # -- status line -----------------------------------------------------
        self.status_label = ctk.CTkLabel(
            outer,
            text="",
            font=ctk.CTkFont(family=self.font_body, size=11),
            text_color=_SAGE,
            wraplength=400,
            justify="left",
        )
        self.status_label.pack(anchor="w", pady=(16, 0))

    def _rule(self, parent, pady):
        line = ctk.CTkFrame(parent, height=1, fg_color=_PANEL_BORDER)
        line.pack(fill="x", pady=pady)

    # customtkinter's CTkSegmentedButton wants its own StringVar reflecting
    # the UPPERCASE display values; keep it in sync with self.style_var
    # (the lowercase value PhraseManager actually expects) via a trace.
    def _style_display_var(self) -> ctk.StringVar:
        display_var = ctk.StringVar(value=self.style_var.get().upper())

        def sync(*_args):
            self.style_var.set(display_var.get().lower())

        display_var.trace_add("write", sync)
        self._display_style_var = display_var
        return display_var

    # Same trace-sync pattern as _style_display_var: CTkSegmentedButton
    # needs its own display-string StringVar; the real value lives in
    # SecurityLevelStore, read once at popup startup.
    def _level_display_var(self) -> ctk.StringVar:
        current = self.security_level_store.get_level()
        display_var = ctk.StringVar(value=f"LEVEL {current}")
        self._level_display_var_ref = display_var
        return display_var

    def _on_level_change(self, value: str):
        level = 1 if "1" in value else 2
        self.security_level_store.set_level(level, notifier=self.notifier)
        self._refresh_allow_list_label()
        if level == 1:
            self._set_status(
                "LEVEL 1 ACTIVE — allow-list is NOT enforced. Any authenticated sender "
                "who knows the phrase can complete a login.",
                is_error=True,
            )
        else:
            self._set_status("Level 2 active — allow-list enforced (default).")

    def _refresh_allow_list_label(self):
        senders = ", ".join(self.config.access["allowed_senders"])
        level = self.security_level_store.get_level()
        if level == 1:
            self.allow_list_label.configure(
                text=f"Allow-list: {senders}  —  NOT ENFORCED WHILE LEVEL 1 IS ACTIVE",
                text_color=_DANGER,
            )
        else:
            self.allow_list_label.configure(text=f"Allow-list (enforced): {senders}", text_color=_DIM)

    def _set_status(self, text: str, is_error: bool = False):
        self.status_label.configure(text=text.upper(), text_color=_DANGER if is_error else _SAGE)

    def _on_generate(self):
        style = self.style_var.get()
        new_phrase = self.phrase_manager.physical_reset(style)
        self._notify_new_phrase(new_phrase)
        self.prefix_label.configure(text=new_phrase.prefix.upper())
        self._set_status(f"Generated new {style} phrase — emailed to you. Prefix: {new_phrase.prefix!r}")

    def _on_custom(self):
        style = self.style_var.get()
        raw = self.custom_entry.get()
        try:
            new_phrase = self.phrase_manager.set_custom_phrase(raw, style)
        except ValueError as e:
            messagebox.showerror("Invalid phrase", str(e))
            return
        self._notify_new_phrase(new_phrase)
        self.prefix_label.configure(text=new_phrase.prefix.upper())
        self.custom_entry.delete(0, "end")
        self._set_status(f"Custom phrase set — emailed to you. Prefix: {new_phrase.prefix!r}")

    def _notify_new_phrase(self, new_phrase):
        self.notifier.send_with_retry(
            subject="Phrase rotated (local popup)",
            body=f"New phrase set from the local popup:\n{new_phrase.full}",
            attempts=1,
        )

    def _on_clear_pending(self):
        for sender in self.config.access["allowed_senders"]:
            self.challenges.clear_pending(sender.lower())
        self._set_status("Cleared any pending challenge for all allowed senders.")


def main():
    config = Config()
    root = ctk.CTk()
    PopupApp(root, config)
    root.mainloop()


if __name__ == "__main__":
    main()
