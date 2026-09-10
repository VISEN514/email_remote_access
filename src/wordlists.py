"""Wordlist loading for the two passphrase styles (PLAN.md section 2).

Diceware: EFF long wordlist, 7776 words, ~12.9 bits/word.
Tactical: fixed 26-word NATO phonetic alphabet + a curated tactical list,
combined pool ~86 words, ~6.4 bits/word -- this is why the tactical suffix
is 7 words where diceware's is 4 (see phrase_manager.py for the entropy math
this sizing is actually based on).
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent

NATO_ALPHABET = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    "india", "juliett", "kilo", "lima", "mike", "november", "oscar", "papa",
    "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey",
    "xray", "yankee", "zulu",
]

# Curated tactical verbs/nouns -- deliberately short/common "radio chatter"
# words, distinct from the NATO alphabet, to round the combined pool to a
# clean, honestly-stated size (see PLAN.md section 2's entropy accounting:
# 26 NATO + 60 tactical = 86 words, log2(86) ~= 6.4 bits/word).
TACTICAL_WORDS = [
    "breach", "extract", "signal", "uplink", "downlink", "channel", "gate",
    "perimeter", "checkpoint", "convoy", "outpost", "beacon", "relay",
    "handshake", "callsign", "rally", "recon", "overwatch", "flank", "advance",
    "retreat", "hold", "cover", "strike", "target", "objective", "sector",
    "grid", "compass", "horizon", "dawn", "dusk", "midnight", "shadow", "ghost",
    "phantom", "sentinel", "vanguard", "spearhead", "anchor", "harbor",
    "bridge", "tunnel", "corridor", "junction", "waypoint", "marker", "flare",
    "smoke", "static", "frequency", "transmit", "receive", "intercept",
    "decode", "cipher", "protocol", "override", "standby", "clearance",
]

TACTICAL_POOL = NATO_ALPHABET + TACTICAL_WORDS


def load_eff_wordlist() -> list[str]:
    """EFF long wordlist, one word per line, dice-index prefix stripped."""
    path = ROOT / "wordlists" / "eff_large_wordlist.txt"
    words = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        words.append(parts[-1])
    if len(words) != 7776:
        raise RuntimeError(f"Expected 7776 words in EFF wordlist, found {len(words)}")
    return words
