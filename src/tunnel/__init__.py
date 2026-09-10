from .base import TunnelProvider
from .cloudflare import CloudflareTunnel
from .tailscale import TailscaleFunnelTunnel


def build_tunnel_provider(config: dict) -> TunnelProvider:
    provider = config.get("provider", "cloudflare")
    if provider == "cloudflare":
        return CloudflareTunnel(cloudflared_path=config.get("cloudflared_path", "cloudflared.exe"))
    if provider == "tailscale":
        return TailscaleFunnelTunnel()
    raise ValueError(f"Unknown tunnel provider: {provider!r}")
