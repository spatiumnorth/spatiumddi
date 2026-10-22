"""Credential health for integration targets (#2138).

One derivation of "is this integration's credential about to stop working?"
shared by the integration's own list response, the Integrations dashboard
row and the IPAM-tab dashboard panel, so the chip cannot read amber on one
surface and green on another (non-negotiable #15). Tailscale is the first
integration to record an expiry; the shape is integration-neutral so the
next one (NetBird personal access tokens, cloud keys) reuses it.

States:

* ``rejected`` — the last sync was refused with HTTP 401: the credential is
  already dead, whatever its recorded expiry says.
* ``expired`` — the recorded expiry has passed.
* ``expiring`` — it passes within :data:`CREDENTIAL_EXPIRY_WARN_DAYS`.
* ``ok`` — a recorded expiry further out than that.
* ``unknown`` — no expiry recorded. Never reported as ``ok``.
* ``disabled`` — the target is switched off (#2191). It syncs nothing, so a
  lapsed credential breaks nothing and ``secret_expiring`` skips it; its last
  rejection is history, not a live problem. This is the ONE place that rule
  lives, so the page, the API, the MCP tool and both dashboards agree.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

# Same 30 days the ``secret_expiring`` rule uses when its threshold is unset,
# so the chip turns amber when the default rule starts warning.
CREDENTIAL_EXPIRY_WARN_DAYS = 30

CREDENTIAL_STATES = ("ok", "expiring", "expired", "rejected", "unknown", "disabled")

# States that need an operator to act (drive tone and ordering on the cards).
CREDENTIAL_PROBLEM_STATES = ("rejected", "expired", "expiring")


@dataclass(frozen=True)
class CredentialStatus:
    state: str
    expires_at: datetime | None
    # Whole days left, rounded down; negative once expired. None when unknown.
    days_left: int | None


def credential_status(
    *, expires_at: datetime | None, rejected: bool, now: datetime, enabled: bool = True
) -> CredentialStatus:
    days_left: int | None = None
    if expires_at is not None:
        days_left = math.floor((expires_at - now).total_seconds() / 86400)
    if not enabled:
        return CredentialStatus("disabled", expires_at, days_left)
    if rejected:
        return CredentialStatus("rejected", expires_at, days_left)
    if expires_at is None:
        return CredentialStatus("unknown", None, None)
    if expires_at <= now:
        return CredentialStatus("expired", expires_at, days_left)
    if days_left is not None and days_left < CREDENTIAL_EXPIRY_WARN_DAYS:
        return CredentialStatus("expiring", expires_at, days_left)
    return CredentialStatus("ok", expires_at, days_left)


__all__ = [
    "CREDENTIAL_EXPIRY_WARN_DAYS",
    "CREDENTIAL_PROBLEM_STATES",
    "CREDENTIAL_STATES",
    "CredentialStatus",
    "credential_status",
]
