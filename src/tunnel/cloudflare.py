import re
import subprocess
import threading
import time

from .base import TunnelProvider

URL_RE = re.compile(r"https://[a-zA-Z0-9\-]+\.trycloudflare\.com")


class CloudflareTunnel(TunnelProvider):
    """Cloudflare 'quick tunnel' -- no account/domain needed. A fresh random
    hostname per process; killing the process permanently retires it, so
    there's nothing to reuse or collide with on the next session."""

    def __init__(self, cloudflared_path: str = "cloudflared.exe"):
        self.cloudflared_path = cloudflared_path
        self._proc: subprocess.Popen | None = None

    def start(self, local_port: int, timeout_seconds: int = 20) -> str:
        self._proc = subprocess.Popen(
            [self.cloudflared_path, "tunnel", "--url", f"http://localhost:{local_port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        found_url = {}

        def _read_output():
            for line in self._proc.stdout:
                match = URL_RE.search(line)
                if match and "url" not in found_url:
                    found_url["url"] = match.group(0)

        threading.Thread(target=_read_output, daemon=True).start()

        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if "url" in found_url:
                return found_url["url"]
            if self._proc.poll() is not None:
                raise RuntimeError("cloudflared exited before producing a tunnel URL")
            time.sleep(0.25)

        self.stop()
        raise TimeoutError("Timed out waiting for cloudflared to report a tunnel URL")

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    @property
    def pid(self) -> int | None:
        if self._proc and self._proc.poll() is None:
            return self._proc.pid
        return None
