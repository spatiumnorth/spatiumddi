"""Host-name guard for integration-mirrored addresses (#1459).

Every read-only integration mirror (UniFi, Docker, Proxmox, the cloud
providers, OPNsense, Kubernetes, Tailscale, NetBird, and the Meraki /
Fortinet / PAN-OS mirrors through ``firewall_mirror``) builds a desired
address whose ``hostname`` it copies from an upstream display name. That
value lands in ``IPAddress.hostname`` and IPAM's DNS sync publishes it as a
record owner verbatim, so "Vitrinen Schalter" became a record the DNS
servers refuse on every attempt.

Each desired-address dataclass calls :func:`normalize_desired_hostname` from
``__post_init__``, so the fold happens once, where the address is built,
and the reconcilers' change detection compares like with like (no rename on
every pass). When the name had to change, the upstream original is kept at
the end of the description, so operators can still find the device by the
name they gave it.
"""

from __future__ import annotations

from typing import Any

from app.core.dns_names import sanitize_mirrored_hostname


def normalize_desired_hostname(desired: Any) -> None:
    """Fold ``desired.hostname`` into a legal host name in place.

    Works on frozen and plain dataclasses alike. A legal name, an empty one
    and ``None`` are left untouched.
    """
    raw = desired.hostname
    if not raw:
        return
    clean = sanitize_mirrored_hostname(raw)
    if clean == raw:
        return
    original = raw.strip()
    description = desired.description or ""
    note = f"name: {original}"
    object.__setattr__(desired, "hostname", clean)
    object.__setattr__(desired, "description", f"{description} — {note}" if description else note)
