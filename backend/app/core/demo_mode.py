"""Demo mode — locks down abusable mutation surfaces.

Enabled via the ``DEMO_MODE=1`` env var (see ``Settings.demo_mode``).
Used by the GitHub Codespaces public-demo deployment to keep the
instance from being weaponised as a scanner / SSRF springboard /
mail relay by anonymous visitors.

What demo mode does:

1. At startup, force a curated set of feature modules off and reject
   PATCH attempts to re-enable them (``DEMO_RESTRICTED_MODULES``).
2. Returns 403 from selected mutation endpoints (factory reset,
   password change, AI provider / webhook / audit-forward / backup
   target / SMTP create + integration target creates). Each gated
   handler imports ``forbid_in_demo_mode`` and calls it inline.
3. Surfaces a ``demo_mode`` flag through ``/health/platform`` so the
   frontend can show a persistent banner.

What demo mode does NOT do:

* Block reads — every list / detail / search endpoint stays open.
* Block IPAM / DNS / DHCP CRUD on the seeded demo data — visitors
  should be able to play with it. The threat model is "anonymous
  demo viewers can't weaponise this", not "everything is read-only".
* Restrict outbound network at the OS layer. Codespaces doesn't
  support that cleanly; mitigation is at the application layer.
"""

from __future__ import annotations

from typing import Final

from fastapi import HTTPException, status

from app.config import settings

# Feature modules that demo mode keeps off and rejects re-enable
# attempts for. nmap is the obvious one (otherwise the demo is a
# free packet-scanning launchpad). AI copilot needs the operator's
# own API keys, which a public demo can't supply safely. The
# integration mirrors all let an attacker point us at internal
# services (SSRF). Conformity / DNS import / network modeling
# stays on so visitors can see what they look like.
DEMO_RESTRICTED_MODULES: Final[frozenset[str]] = frozenset(
    {
        "tools.nmap",
        "tools.pcap",
        "ai.copilot",
        "integrations.kubernetes",
        "integrations.docker",
        "integrations.proxmox",
        "integrations.tailscale",
        "integrations.unifi",
        "integrations.cloud",
        "integrations.vsphere",
    }
)


def is_demo_mode() -> bool:
    """Tests + tooling can monkeypatch ``settings.demo_mode`` rather
    than re-importing this module."""
    return bool(settings.demo_mode)


def forbid_in_demo_mode(reason: str = "Disabled in demo mode") -> None:
    """Raise 403 if demo mode is active. Call inline at the top of
    handlers that should be locked down. ``reason`` is included in
    the response detail so consumers see something more informative
    than a bare 403."""
    if is_demo_mode():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{reason} (this instance is running in demo mode)",
        )
