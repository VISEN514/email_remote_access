import json
import os
import tempfile
import threading
import time
from pathlib import Path

from file_perms import restrict_to_current_user

try:
    import msvcrt
except ImportError:  # pragma: no cover -- this project targets Windows
    msvcrt = None

_CROSS_PROCESS_LOCK_TIMEOUT_SECONDS = 10
_CROSS_PROCESS_LOCK_POLL_SECONDS = 0.05


class _CrossProcessFileLockHandle:
    """The actual acquired lock for ONE `with` block. Deliberately a fresh
    object per acquisition (see _CrossProcessFileLock.acquire()) rather than
    state stored on a long-lived shared instance -- StateStore's
    threading.Lock already serializes concurrent THREADS within one process
    down to one acquirer at a time, but each of those threads calls
    acquire() and gets its own handle/file descriptor, so there's no shared
    mutable state for them to race on here."""

    def __init__(self, lock_path: Path):
        self._lock_path = lock_path
        self._fh = None

    def __enter__(self):
        if msvcrt is None:
            return self
        self._fh = open(self._lock_path, "a+b")
        if os.fstat(self._fh.fileno()).st_size == 0:
            self._fh.write(b"0")
            self._fh.flush()
        self._fh.seek(0)
        deadline = time.time() + _CROSS_PROCESS_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                return self
            except OSError:
                if time.time() > deadline:
                    self._fh.close()
                    raise TimeoutError(f"Timed out waiting for cross-process lock on {self._lock_path}")
                time.sleep(_CROSS_PROCESS_LOCK_POLL_SECONDS)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if msvcrt is None:
            return False
        try:
            self._fh.seek(0)
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self._fh.close()
        return False


class _CrossProcessFileLock:
    """A real OS-level lock, separate from StateStore's in-process
    threading.Lock. That in-process lock only protects callers holding the
    SAME StateStore instance (see SessionBroker's own docstring on this) --
    it provides zero protection between two different processes (main.py's
    daemon and popup_app.py's Tkinter process) each constructing their own
    StateStore pointed at the identical file, which is exactly what
    popup_app.py does. Without this, a popup write (e.g. 'clear stuck
    pending challenge') racing the daemon's own concurrent update could
    silently lose one of the two writes to a plain last-os.replace-wins
    clobber -- including resurrecting an already-consumed challenge.

    Uses msvcrt.locking on a sibling `.lock` file (Windows-only, matching
    this project's target platform) as a simple, dependency-free
    inter-process mutex around the read-modify-write in update() (and read(),
    so a read can never observe another process's write half-applied). This
    object is just a stateless factory -- see acquire() -- so it's safe to
    share across threads."""

    def __init__(self, path: Path):
        self._lock_path = path.with_suffix(path.suffix + ".lock")

    def acquire(self) -> _CrossProcessFileLockHandle:
        return _CrossProcessFileLockHandle(self._lock_path)


class StateStore:
    """Small on-disk JSON store with atomic writes (write-temp-then-rename),
    used for lockout counters and session-active reconciliation so a crash
    can't leave a half-written, corrupt state file. Also guards every
    read/update with a cross-process file lock (see _CrossProcessFileLock)
    -- this file is written by more than one process (main.py's daemon and
    popup_app.py), not just multiple threads within one."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._cross_process_lock = _CrossProcessFileLock(self.path)
        if not self.path.exists():
            self._write({})

    def _write(self, data: dict):
        fd, tmp_path = tempfile.mkstemp(dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise
        restrict_to_current_user(str(self.path))

    def read(self) -> dict:
        with self._cross_process_lock.acquire(), self._lock:
            if not self.path.exists():
                return {}
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}

    def update(self, mutate_fn):
        """mutate_fn(data: dict) -> dict, applied and persisted atomically
        under BOTH the in-process lock (protects concurrent callers sharing
        this exact instance) AND the cross-process file lock (protects
        against a different process, e.g. popup_app.py, holding its own
        separate StateStore instance on the same file)."""
        with self._cross_process_lock.acquire(), self._lock:
            try:
                data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
            except (json.JSONDecodeError, OSError):
                data = {}
            data = mutate_fn(data)
            self._write(data)
            return data
