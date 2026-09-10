from abc import ABC, abstractmethod


class TunnelProvider(ABC):
    """Exposes a local port to the internet on demand, for one session's
    lifetime. Nothing else in the system depends on which provider is active."""

    @abstractmethod
    def start(self, local_port: int) -> str:
        raise NotImplementedError

    @abstractmethod
    def stop(self):
        raise NotImplementedError

    @property
    def pid(self) -> int | None:
        """PID of the underlying tunnel process, if one is currently
        running, else None. Exists so the broker can persist enough
        identity to find and terminate an orphaned tunnel process across a
        crash/restart -- without this, a broker restart has no way to even
        locate the tunnel process it started, let alone tear it down."""
        raise NotImplementedError
