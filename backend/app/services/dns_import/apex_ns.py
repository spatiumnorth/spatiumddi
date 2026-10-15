"""Apex NS handling for imported zones (#1892).

A zone imported from another server arrives with that server's apex NS set
(``@ NS tech1.example.``) in its records. After import the zone's agent serves
those rows as the zone's whole NS set (#1153), so the managed zone stays
delegated to the host it was migrated off, and goes lame when that host is
retired. Drift cannot see it, because the agent serves exactly what the rows
say.

The model:

* An apex NS is **foreign** when its target is not one of the target group's
  servers (matched on the server's ``name`` or ``host``). Preview reports
  foreign apex NS per zone; nothing changes by default, because an apex NS can
  be deliberate (a zone served from hostnames SpatiumDDI does not know the
  group's servers by) and an existing install keeps its rows as they are.
* ``apex_ns_policy="replace"`` is the operator's explicit choice. At commit
  the foreign apex NS rows are not imported, the group's servers whose ``host``
  is a usable hostname become the apex NS set, and a SOA primary name that was
  foreign follows. Delegations below the apex are never touched. If the group
  has no server with a usable hostname the zone is left as imported and the
  commit says so: replacing with nothing would make the agent fall back to a
  placeholder NS glued to loopback, which is worse than the source's name.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass, replace
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer

from .canonical import ImportedRecord, ImportedZone, ImportPreview

ApexNsPolicy = Literal["keep", "replace"]

_LABEL = r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?"
_HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})+$")


def _norm(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _is_apex(r: ImportedRecord, zone_name: str) -> bool:
    """An NS at the apex: ``@``, empty, or the zone's own name. The plan
    round-trips through the client, so the FQDN spelling is accepted too."""
    if r.record_type.upper() != "NS":
        return False
    owner = (r.name or "").strip()
    return owner in ("@", "") or _norm(owner) == _norm(zone_name)


def _target_forms(value: str, zone_name: str) -> set[str]:
    """Names an NS value can mean: as written, and relative to the zone when
    it carries no trailing dot (zone-file semantics)."""
    forms = {_norm(value)}
    if not value.strip().endswith("."):
        forms.add(_norm(value) + "." + _norm(zone_name))
    return forms


@dataclass
class GroupNames:
    known: set[str]  # name + host of every server in the group
    usable_hosts: list[str]  # enabled servers whose host is a DNS hostname
    has_servers: bool = True


async def group_names(db: AsyncSession, group_id: uuid.UUID) -> GroupNames:
    servers = (
        (
            await db.execute(
                select(DNSServer).where(DNSServer.group_id == group_id).order_by(DNSServer.name)
            )
        )
        .scalars()
        .all()
    )
    known: set[str] = set()
    usable: list[str] = []
    for s in servers:
        for n in (s.name, s.host):
            if n:
                known.add(_norm(n))
        host = _norm(s.host or "")
        if not s.is_enabled or host in usable or not _HOSTNAME_RE.match(host):
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError:
            usable.append(host)
    return GroupNames(known=known, usable_hosts=usable, has_servers=bool(servers))


def foreign_apex_ns(zone: ImportedZone, names: GroupNames) -> list[ImportedRecord]:
    """Apex NS rows of a primary zone naming no server of the target group.

    A group with no servers yet has nothing to compare against (and nothing
    to replace with), so nothing is reported for it."""
    if zone.zone_type != "primary" or not names.has_servers:
        return []
    return [
        r
        for r in zone.records
        if _is_apex(r, zone.name) and not (_target_forms(r.value, zone.name) & names.known)
    ]


async def annotate_apex_ns(
    db: AsyncSession, preview: ImportPreview, target_group_id: uuid.UUID
) -> None:
    """Record, per zone, the apex NS naming a host outside the target group
    (``ImportedZone.foreign_apex_ns``, which the UI offers the replace choice
    from) and add one preview warning for each such zone. Read-only: the
    zone's records are not changed."""
    names = await group_names(db, target_group_id)
    for z in preview.zones:
        foreign = foreign_apex_ns(z, names)
        if not foreign:
            continue
        hosts = sorted({_norm(r.value) for r in foreign})
        z.foreign_apex_ns = hosts
        preview.warnings.append(
            f"{_warning_prefix(z.name)}{', '.join(hosts)}, which is not a server in the "
            "target group. The imported zone stays delegated to that host and goes lame "
            "once it is retired. Commit with apex_ns_policy='replace' to serve the "
            "group's own servers as the zone's NS set instead."
        )


def _warning_prefix(zone_name: str) -> str:
    return f"Zone {zone_name!r}: apex NS names "


def is_apex_ns_warning(warning: str, zone_name: str) -> bool:
    """Whether ``warning`` is the preview's apex NS warning for ``zone_name``;
    the commit drops it for a zone whose NS it replaced, since the plan's
    warnings round-trip into the commit result."""
    return warning.startswith(_warning_prefix(zone_name))


def replace_apex_ns(
    zone: ImportedZone, names: GroupNames
) -> tuple[ImportedZone, dict[str, Any] | None, str | None]:
    """Apply ``apex_ns_policy="replace"`` to one zone.

    Returns ``(zone, change, warning)``. ``change`` is the audit detail (None
    when nothing was replaced); ``warning`` is set when foreign NS exist but
    cannot be replaced.
    """
    foreign = foreign_apex_ns(zone, names)
    if not foreign:
        return zone, None, None
    if not names.usable_hosts:
        return (
            zone,
            None,
            f"Zone {zone.name!r}: apex NS kept as imported, the target group has no enabled "
            "server with a hostname to replace it with",
        )
    drop = {id(r) for r in foreign}
    kept = [r for r in zone.records if id(r) not in drop]
    have = {_norm(r.value) for r in kept if _is_apex(r, zone.name)}
    ttl = foreign[0].ttl
    added = [h for h in names.usable_hosts if h not in have]
    kept.extend(ImportedRecord(name="@", record_type="NS", value=h + ".", ttl=ttl) for h in added)
    soa = zone.soa
    if soa is not None and not (_target_forms(soa.primary_ns, zone.name) & names.known):
        soa = replace(soa, primary_ns=names.usable_hosts[0] + ".")
    change: dict[str, Any] = {
        "removed": [r.value for r in foreign],
        "added": [h + "." for h in added],
        "primary_ns": soa.primary_ns if soa is not None else None,
    }
    return replace(zone, records=kept, soa=soa, apex_ns_replaced=change), change, None
