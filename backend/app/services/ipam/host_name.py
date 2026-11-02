"""When an address's stored ``fqdn`` is its current name (#3297).

Clearing an address's hostname retracts the DNS it published but
deliberately keeps ``ip_address.fqdn`` (and the zone ids), so an orphan row
keeps showing what was published and a restore knows where to put the
records back. The consequence is that a live row with no hostname can still
carry an old ``fqdn``. Every reader that presents the name *as current*
goes through :func:`current_fqdn`; only the orphan / restore surfaces read
the stored column directly.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, func
from sqlalchemy.sql.elements import ColumnElement

from app.models.ipam import IPAddress


def current_fqdn(hostname: str | None, fqdn: str | None) -> str | None:
    """``fqdn`` when the row still has a hostname, else ``None``."""
    if hostname and hostname.strip():
        return fqdn
    return None


def fqdn_matches(pattern_clause: Any) -> ColumnElement[bool]:
    """SQL guard: *pattern_clause* (a condition on ``IPAddress.fqdn``) only
    counts for a row that has a hostname."""
    return and_(func.coalesce(func.trim(IPAddress.hostname), "") != "", pattern_clause)
