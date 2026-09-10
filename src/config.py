from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.yaml"

# Required top-level sections and the keys each must contain -- validated at
# startup so a missing config value fails loudly and clearly here, rather
# than surfacing as an unguided KeyError deep inside an unrelated module at
# runtime (a single-owner system should fail helpfully at boot).
_REQUIRED_SCHEMA = {
    "gmail": ["credentials_path", "token_path", "poll_interval_seconds", "trusted_authserv_id"],
    "access": [
        "phrase_path", "phrase_next_path", "allowed_senders", "max_failed_attempts", "lockout_minutes",
        "default_security_level",
    ],
    "session": [
        "idle_timeout_minutes",
        "absolute_timeout_minutes",
        "local_web_port_range",
        "vnc_host",
        "vnc_port",
        "state_path",
    ],
    "flood": ["threshold_per_cycle"],
    "tunnel": ["provider"],
    "notify": ["alert_to"],
}


class Config:
    def __init__(self, path: Path = CONFIG_PATH):
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found. Copy config.example.yaml to config.yaml and fill it in."
            )
        with open(path, "r", encoding="utf-8") as f:
            self._raw = yaml.safe_load(f) or {}
        self._validate()

    def _validate(self):
        errors = []
        for section, keys in _REQUIRED_SCHEMA.items():
            if section not in self._raw:
                errors.append(f"missing top-level section: {section!r}")
                continue
            for key in keys:
                if key not in self._raw[section]:
                    errors.append(f"missing key {key!r} in section {section!r}")
        if not self._raw.get("access", {}).get("allowed_senders"):
            errors.append("access.allowed_senders must be a non-empty list")
        if errors:
            raise ValueError(
                "config.yaml is invalid:\n  - "
                + "\n  - ".join(errors)
                + f"\nSee config.example.yaml at {ROOT / 'config.example.yaml'}"
            )

    def __getitem__(self, key):
        return self._raw[key]

    @property
    def gmail(self):
        return self._raw["gmail"]

    @property
    def access(self):
        return self._raw["access"]

    @property
    def session(self):
        return self._raw["session"]

    @property
    def flood(self):
        return self._raw["flood"]

    @property
    def tunnel(self):
        return self._raw["tunnel"]

    @property
    def notify(self):
        return self._raw["notify"]

    @property
    def heartbeat(self):
        return self._raw.get("heartbeat", {})
