"""Cutover-rehearsal diff for the commercial-DDI mirror (#4729).

Compares one target's mirrored objects with LIVE SpatiumDDI rows and says, per
object, what an import would do: ``create`` (nothing live matches), ``exists``
(a live row matches) or ``differs`` (a live row matches by identity but not by
content). Read-only on both sides and computed on demand, so it is always
current and never persisted.

Matching, all against live (non-Trashed) rows:

* container -> ``IPBlock`` by CIDR; network -> ``Subnet`` by CIDR.
* range -> ``DHCPPool`` by start / end address.
* fixed address -> ``IPAddress`` by address (MAC and hostname compared).
* zone -> ``DNSZone`` by name; view -> ``DNSView`` by name.
* host / A -> ``A`` records by FQDN (host records: one per address); PTR -> ``PTR``
  records by FQDN. A record matches on value; a different value is ``differs``.

Soft-deleted rows are excluded by the session's default filter, so a Trashed
twin never counts as "exists".
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ddi_mirror import DDIMirrorObject
from app.models.dhcp import DHCPPool
from app.models.dns import DNSRecord, DNSView, DNSZone
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.services.ddi_mirror.base import (
    ALL_KINDS,
    KIND_A,
    KIND_CONTAINER,
    KIND_HOST,
    KIND_NETWORK,
    KIND_PTR,
    KIND_RANGE,
    KIND_RESERVATION,
    KIND_VIEW,
    KIND_ZONE,
)

ACTIONS: tuple[str, ...] = ("create", "exists", "differs")
_CHUNK = 1000


@dataclass
class RehearsalItem:
    kind: str
    name: str
    value: str
    view: str
    action: str
    differences: list[str] = field(default_factory=list)


@dataclass
class KindCounts:
    total: int = 0
    create: int = 0
    exists: int = 0
    differs: int = 0


def _chunks(values: list[str]) -> Iterator[list[str]]:
    for i in range(0, len(values), _CHUNK):
        yield values[i : i + _CHUNK]


def _fqdn(name: str) -> str:
    return name.rstrip(".").lower() + "."


def _norm(name: str | None) -> str:
    return (name or "").rstrip(".").lower()


async def _ip_rows(db: AsyncSession, ips: list[str]) -> dict[str, list[IPAddress]]:
    out: dict[str, list[IPAddress]] = {}
    for chunk in _chunks(sorted(set(ips))):
        rows = (
            (await db.execute(select(IPAddress).where(func.host(IPAddress.address).in_(chunk))))
            .scalars()
            .all()
        )
        for r in rows:
            out.setdefault(str(r.address).split("/")[0], []).append(r)
    return out


def _ip_diff(rows: list[IPAddress], *, mac: str, hostname: str) -> list[str]:
    """Differences against the best-matching live row (any row that agrees wins)."""
    best: list[str] | None = None
    for r in rows:
        diffs: list[str] = []
        if mac and r.mac_address and str(r.mac_address).lower() != mac.lower():
            diffs.append(f"MAC {r.mac_address} live vs {mac} on the source")
        if hostname and r.hostname and _norm(r.hostname) != _norm(hostname).split(".")[0]:
            if _norm(r.hostname) != _norm(hostname):
                diffs.append(f"hostname {r.hostname} live vs {hostname} on the source")
        if not diffs:
            return []
        best = diffs if best is None else best
    return best or []


async def _records(db: AsyncSession, rtype: str, fqdns: list[str]) -> dict[str, list[DNSRecord]]:
    out: dict[str, list[DNSRecord]] = {}
    wanted = sorted({_fqdn(f) for f in fqdns})
    for chunk in _chunks(wanted):
        rows = (
            (
                await db.execute(
                    select(DNSRecord).where(
                        DNSRecord.record_type == rtype, func.lower(DNSRecord.fqdn).in_(chunk)
                    )
                )
            )
            .scalars()
            .all()
        )
        for r in rows:
            out.setdefault(_norm(r.fqdn), []).append(r)
    return out


def _item(o: DDIMirrorObject, action: str, diffs: list[str] | None = None) -> RehearsalItem:
    return RehearsalItem(o.kind, o.name, o.value, o.view, action, diffs or [])


def _record_item(
    o: DDIMirrorObject, live: list[DNSRecord], value: str, *, strip_dot: bool
) -> RehearsalItem:
    if not live:
        return _item(o, "create")
    for r in live:
        got = _norm(r.value) if strip_dot else (r.value or "").strip()
        if got == value:
            return _item(o, "exists")
    return _item(o, "differs", [f"live value {live[0].value} vs {value} on the source"])


async def _kind_items(
    db: AsyncSession, kind: str, rows: list[DDIMirrorObject]
) -> list[RehearsalItem]:
    if not rows:
        return []

    if kind == KIND_VIEW:
        names = {n for n in (await db.execute(select(DNSView.name))).scalars().all()}
        return [_item(o, "exists" if o.name in names else "create") for o in rows]

    if kind == KIND_ZONE:
        zones = {_norm(n) for n in (await db.execute(select(DNSZone.name))).scalars().all()}
        return [_item(o, "exists" if _norm(o.name) in zones else "create") for o in rows]

    if kind == KIND_CONTAINER:
        blocks = {str(n) for n in (await db.execute(select(IPBlock.network))).scalars().all()}
        return [_item(o, "exists" if o.value in blocks else "create") for o in rows]

    if kind == KIND_NETWORK:
        subs = {
            str(n): (name, desc)
            for n, name, desc in (
                await db.execute(select(Subnet.network, Subnet.name, Subnet.description))
            ).all()
        }
        blocks = {str(n) for n in (await db.execute(select(IPBlock.network))).scalars().all()}
        out = []
        for o in rows:
            hit = subs.get(o.value)
            if hit is None:
                if o.value in blocks:
                    out.append(
                        _item(o, "differs", ["live has this prefix as a block, not a subnet"])
                    )
                else:
                    out.append(_item(o, "create"))
            elif o.comment and o.comment not in hit:
                out.append(
                    _item(
                        o, "differs", [f"comment {o.comment!r} is not the live name or description"]
                    )
                )
            else:
                out.append(_item(o, "exists"))
        return out

    if kind == KIND_RANGE:
        pools = {
            (str(s).split("/")[0], str(e).split("/")[0])
            for s, e in (await db.execute(select(DHCPPool.start_ip, DHCPPool.end_ip))).all()
        }
        return [
            _item(o, "exists" if (o.data.get("start"), o.data.get("end")) in pools else "create")
            for o in rows
        ]

    if kind == KIND_RESERVATION:
        by_ip = await _ip_rows(db, [o.value for o in rows])
        out = []
        for o in rows:
            live_ips = by_ip.get(o.value)
            if not live_ips:
                out.append(_item(o, "create"))
                continue
            diffs = _ip_diff(live_ips, mac=str(o.data.get("mac", "")), hostname=o.name)
            out.append(_item(o, "differs", diffs) if diffs else _item(o, "exists"))
        return out

    if kind in (KIND_HOST, KIND_A):
        recs = await _records(db, "A", [o.name for o in rows])
        out = []
        for o in rows:
            addrs = (
                [a["ip"] for a in o.data.get("addresses", [])] if kind == KIND_HOST else [o.value]
            )
            items = [
                _record_item(o, recs.get(_norm(o.name), []), ip, strip_dot=False) for ip in addrs
            ]
            diffs = [d for i in items for d in i.differences]
            creates = [i for i in items if i.action == "create"]
            if diffs:
                out.append(_item(o, "differs", diffs))
            elif creates and len(creates) == len(items):
                out.append(_item(o, "create"))
            elif creates:
                out.append(_item(o, "differs", ["some of its addresses have no live A record"]))
            else:
                out.append(_item(o, "exists"))
        return out

    if kind == KIND_PTR:
        recs = await _records(db, "PTR", [o.name for o in rows])
        return [
            _record_item(o, recs.get(_norm(o.name), []), _norm(o.value), strip_dot=True)
            for o in rows
        ]

    return []


def _kinds(selected: Iterable[str] | None) -> list[str]:
    return [k for k in ALL_KINDS if selected is None or k in set(selected)]


async def build_rehearsal(
    db: AsyncSession,
    target_id: uuid.UUID,
    *,
    kind: str | None = None,
    action: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[dict[str, KindCounts], int, list[RehearsalItem]]:
    """Returns ``(counts per kind, total matching the filters, the requested page)``.

    The counts always cover every kind (the filters only narrow the item list)
    so the summary never changes while an operator filters."""
    counts: dict[str, KindCounts] = {}
    matching = 0
    page: list[RehearsalItem] = []
    for k in _kinds(None):
        rows = list(
            (
                await db.execute(
                    select(DDIMirrorObject)
                    .where(DDIMirrorObject.target_id == target_id, DDIMirrorObject.kind == k)
                    .order_by(DDIMirrorObject.name, DDIMirrorObject.source_ref)
                )
            )
            .scalars()
            .all()
        )
        c = counts.setdefault(k, KindCounts())
        for item in await _kind_items(db, k, rows):
            c.total += 1
            setattr(c, item.action, getattr(c, item.action) + 1)
            if (kind and k != kind) or (action and item.action != action):
                continue
            if offset <= matching < offset + limit:
                page.append(item)
            matching += 1
    return counts, matching, page


__all__ = ["ACTIONS", "KindCounts", "RehearsalItem", "build_rehearsal"]
