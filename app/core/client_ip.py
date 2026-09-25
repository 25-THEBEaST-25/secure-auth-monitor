import ipaddress

from fastapi import Request

from app.core.config import settings


def _parse(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _trusted(addr) -> bool:
    return any(addr in net for net in settings.trusted_proxy_networks)


def get_client_ip(request: Request) -> str:
    """The address rate limits are keyed on.

    X-Forwarded-For is only honoured when the direct peer is a configured
    trusted proxy; otherwise any client could spoof a fresh IP per request and
    dodge IP blocking. The chain is walked right to left, skipping our own
    proxies, and the first address not belonging to them is the client.
    """
    peer = request.client.host if request.client else "unknown"
    peer_addr = _parse(peer)
    if peer_addr is None or not _trusted(peer_addr):
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    hops = [h for h in forwarded.split(",") if h.strip()]
    for hop in reversed(hops):
        addr = _parse(hop)
        if addr is None:
            # Garbage in the chain: stop trusting anything further left.
            break
        if not _trusted(addr):
            return str(addr)
    return peer
