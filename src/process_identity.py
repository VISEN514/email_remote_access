"""PID-reuse-safe process identity (PLAN.md crash/restart reconciliation).

A bare PID is not a safe way to say "is this the same process I started" --
Windows reuses PIDs, and a naive "is this PID alive" check can wrongly adopt
an unrelated process after a reboot. We additionally record the process's
start time and executable path at capture time, and require both to still
match on reconciliation.
"""
import psutil


class ProcessIdentity:
    def __init__(self, pid: int, create_time: float, exe: str):
        self.pid = pid
        self.create_time = create_time
        self.exe = exe

    def to_dict(self) -> dict:
        return {"pid": self.pid, "create_time": self.create_time, "exe": self.exe}

    @classmethod
    def from_dict(cls, data: dict) -> "ProcessIdentity":
        return cls(data["pid"], data["create_time"], data["exe"])

    @classmethod
    def capture(cls, pid: int) -> "ProcessIdentity":
        p = psutil.Process(pid)
        return cls(pid, p.create_time(), p.exe())

    def is_still_this_process(self) -> bool:
        try:
            p = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            return False
        try:
            return p.create_time() == self.create_time and p.exe() == self.exe
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def terminate_if_orphaned(self):
        """Force-clean a process only if it's confirmed to be the one we recorded."""
        if not self.is_still_this_process():
            return
        try:
            psutil.Process(self.pid).terminate()
        except psutil.NoSuchProcess:
            pass
