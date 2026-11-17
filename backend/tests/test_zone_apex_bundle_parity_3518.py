"""The served apex equals what the agent renders from the REAL bundle (#3518).

``test_zone_apex_parity_3518`` feeds both copies of the rule the same
hand-written inputs. That cannot see a difference in the INPUTS: which records
reach the agent (an ingest mirror does, #2850) and that under split-horizon the
agent renders the apex once per view, from that view's records. Here the
bundle is built by ``build_config_bundle``, the agent's ``_zone_apex`` runs on
every zone copy in it, and the records list must report the same thing.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.ingest import EXTERNAL_IMPORT_SOURCE

_AGENT_ROOT = Path(__file__).parents[2] / "agent/dns"

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not (_AGENT_ROOT / "spatium_dns_agent").exists(),
        reason="agent package not in this checkout",
    ),
]


def _agent_zone_apex() -> Any:
    sys.path.insert(0, str(_AGENT_ROOT))
    try:
        from spatium_dns_agent.drivers import bind9
    finally:
        sys.path.remove(str(_AGENT_ROOT))
    return bind9._zone_apex


async def _hdr(db: AsyncSession) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    u = User(
        username=f"a-{tag}",
        email=f"{tag}@example.test",
        display_name="a",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession) -> tuple[DNSServerGroup, DNSServer]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id, name="ns", driver="bind9", host="10.0.0.53", port=53, is_primary=True
    )
    db.add(server)
    await db.flush()
    return group, server


def _zone(group: DNSServerGroup, name: str, **kw: Any) -> DNSZone:
    return DNSZone(group_id=group.id, name=name, zone_type="primary", kind="forward", **kw)


def _rec(
    zone: DNSZone,
    name: str,
    rtype: str,
    value: str,
    *,
    view: DNSView | None = None,
    source: str | None = None,
) -> DNSRecord:
    base = zone.name.rstrip(".")
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=base if name == "@" else f"{name}.{base}",
        record_type=rtype,
        value=value,
        view_id=view.id if view is not None else None,
        import_source=source,
    )


def _agent_view(apex: Any, ns_from_records: list[str]) -> dict[str, Any]:
    """The agent's verdict in the records list's shape. A declared NS set is
    written with the zone's records (``apex.ns`` is empty then)."""
    return {
        "soa": {"mname": apex.soa_mname, "rname": apex.soa_rname},
        "ns": list(apex.ns) if apex.ns else ns_from_records,
        "placeholder_glue_loopback": apex.placeholder_glue,
        # #3670: the agent's own notes on why.
        "unaddressed_primary_ns": next(
            (d for k, d in apex.notes if k == "unaddressed_primary_ns"), None
        ),
        "unaddressed_ns": [d for k, d in apex.notes if k == "unaddressed_ns"],
    }


def _declared(zone_copy: dict[str, Any]) -> list[str]:
    origin = zone_copy["name"] if zone_copy["name"].endswith(".") else zone_copy["name"] + "."
    out = []
    for r in zone_copy.get("records") or []:
        if str(r["type"]).upper() == "NS" and r["name"] in ("@", "", origin):
            v = r["value"]
            out.append(v if v.endswith(".") else f"{v}.{origin}")
    return out


async def _compare(
    client: AsyncClient, db: AsyncSession, server: DNSServer, zones: list[DNSZone]
) -> None:
    zone_apex = _agent_zone_apex()
    hdr = await _hdr(db)
    await db.commit()
    bundle = await build_config_bundle(db, server)
    rendered: dict[str, dict[str | None, dict[str, Any]]] = {}
    for copy in bundle["zones"]:
        if copy.get("type") != "primary":
            continue
        rendered.setdefault(copy["name"], {})[copy.get("view_name")] = _agent_view(
            zone_apex(copy), _declared(copy)
        )
    for zone in zones:
        body = (
            await client.get(
                f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records", headers=hdr
            )
        ).json()
        served = body["served_apex"]
        per_view = rendered[zone.name]
        if served.get("by_view"):
            got = {
                v["view"]: {
                    "soa": v["soa"],
                    "ns": v["ns"],
                    "placeholder_glue_loopback": v["placeholder_glue_loopback"],
                    "unaddressed_primary_ns": v["unaddressed_primary_ns"],
                    "unaddressed_ns": v["unaddressed_ns"],
                }
                for v in served["by_view"]
            }
            assert got == per_view, zone.name
        else:
            want = {
                "soa": served["soa"],
                "ns": served["ns"],
                "placeholder_glue_loopback": served["placeholder_glue_loopback"],
                "unaddressed_primary_ns": served["unaddressed_primary_ns"],
                "unaddressed_ns": served["unaddressed_ns"],
            }
            for view_name, agent in per_view.items():
                assert agent == want, (zone.name, view_name)


async def test_flat_group(client: AsyncClient, db_session: AsyncSession) -> None:
    group, server = await _group(db_session)
    bare = _zone(group, "bare.example.com.")
    prim = _zone(group, "prim.example.com.", primary_ns="ns9.prim.example.com.")
    mirrored = _zone(group, "mirror.example.com.")
    # Two apex NS and no Primary NS: the SOA MNAME is the first in the
    # bundle's record order, not the order the rows were written in.
    multi = _zone(group, "multi.example.com.")
    # An in-zone Primary NS addressed by an absolute owner name, in mixed case.
    absolute = _zone(group, "abs.example.com.", primary_ns="NS9.abs.example.com")
    # The placeholder's own address is the operator's: no loopback glue.
    own_ns1 = _zone(group, "own.example.com.")
    db_session.add_all([bare, prim, mirrored, multi, absolute, own_ns1])
    await db_session.flush()
    db_session.add(_rec(multi, "@", "NS", "ns-b.example.net."))
    await db_session.flush()
    db_session.add_all(
        [
            _rec(multi, "@", "NS", "ns-a.example.net."),
            _rec(absolute, "ns9.ABS.example.com.", "AAAA", "2001:db8::9"),
            _rec(own_ns1, "NS1", "A", "192.0.2.53"),
            _rec(prim, "ns9", "A", "192.0.2.9"),
            _rec(prim, "www", "A", "192.0.2.1"),
            # An ingest mirror of an NS a third party added by RFC 2136 reaches
            # the bundle (#2850), so the agent counts it as declared.
            _rec(mirrored, "@", "NS", "ns-ext.example.net.", source=EXTERNAL_IMPORT_SOURCE),
        ]
    )
    await _compare(client, db_session, server, [bare, prim, absolute, own_ns1])
    await _compare(client, db_session, server, [multi])
    await _compare(client, db_session, server, [mirrored])


async def test_split_horizon_renders_the_apex_per_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group, server = await _group(db_session)
    internal = DNSView(group_id=group.id, name="internal", match_clients=["10.0.0.0/8"], order=0)
    external = DNSView(group_id=group.id, name="external", match_clients=["any"], order=1)
    db_session.add_all([internal, external])
    await db_session.flush()
    # NS declared in one view only: the other view serves the placeholder,
    # glued to loopback.
    split = _zone(group, "split.example.com.")
    # Every apex input shared: one apex, in both views.
    shared = _zone(group, "shared.example.com.", primary_ns="ns.provider.net.")
    db_session.add_all([split, shared])
    await db_session.flush()
    db_session.add_all(
        [
            _rec(split, "@", "NS", "ns-int.example.com.", view=internal),
            _rec(split, "www", "A", "192.0.2.1", view=external),
            _rec(shared, "www", "A", "192.0.2.2"),
        ]
    )
    await _compare(client, db_session, server, [split, shared])
