from .base import TunnelProvider


class TailscaleFunnelTunnel(TunnelProvider):
    """Phase 2, not implemented -- stubbed so the swap point already exists."""

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "Tailscale Funnel tunnel provider is not implemented yet -- "
            "set tunnel.provider: cloudflare in config.yaml for now."
        )

    def start(self, local_port: int) -> str:
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError

    @property
    def pid(self) -> int | None:
        raise NotImplementedError
