"""One network / broadcast rule for Split, Merge and Resize (#2976, #2977, #2978)."""

from __future__ import annotations

import ipaddress
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam.resize import (
    ResizeError,
    commit_subnet_resize,
    preview_block_resize,
    preview_subnet_resize,
)
from app.services.ipam.subnet_boundary import boundary_rows
from app.services.ipam.subnet_merge import MergeError, commit_subnet_merge, preview_subnet_merge
from app.services.ipam.subnet_split import SplitError, commit_subnet_split, preview_subnet_split
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _space_block(db: AsyncSession, block_cidr: str) -> tuple[IPSpace, IPBlock]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=block_cidr, name="b")
    db.add(block)
    await db.flush()
    return space, block


async def _subnet(db, space, block, cidr, **kw) -> Subnet:
    s = Subnet(space_id=space.id, block_id=block.id, network=cidr, name="s", total_ips=2, **kw)
    db.add(s)
    await db.flush()
    return s


def _row(subnet, addr, status="allocated", desc="", host=None):
    return IPAddress(
        subnet_id=subnet.id, address=addr, status=status, description=desc, hostname=host
    )


async def _rows(db, subnet_id) -> dict[str, str]:
    res = await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet_id))
    return {str(r.address): r.status for r in res.scalars().all()}


@pytest.mark.asyncio
async def test_merge_of_two_full_31s_is_refused_naming_the_hosts(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    a = await _subnet(db_session, space, block, "10.233.3.8/31")
    b = await _subnet(db_session, space, block, "10.233.3.10/31")
    for addr in ("10.233.3.8", "10.233.3.9"):
        db_session.add(_row(a, addr))
    for addr in ("10.233.3.10", "10.233.3.11"):
        db_session.add(_row(b, addr))
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    details = [c.detail for c in preview.conflicts if c.type == "host_on_merged_boundary"]
    assert any("10.233.3.8" in d and "network" in d for d in details)
    assert any("10.233.3.11" in d and "broadcast" in d for d in details)
    with pytest.raises(MergeError) as exc:
        await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.233.3.8/30")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_merge_of_31s_without_hosts_on_boundary_gets_rows(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    a = await _subnet(db_session, space, block, "10.233.3.8/31")
    b = await _subnet(db_session, space, block, "10.233.3.10/31")
    db_session.add(_row(a, "10.233.3.9"))
    db_session.add(_row(b, "10.233.3.10", status="network"))  # operator placeholder, not a host
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert not [c for c in preview.conflicts if c.type == "host_on_merged_boundary"]


@pytest.mark.asyncio
async def test_ipv6_split_keeps_network_rows_and_refuses_boundary_host(db_session):
    space, block = await _space_block(db_session, "fd33:233::/32")
    parent = await _subnet(db_session, space, block, "fd33:233:0:101::/64")
    db_session.add(_row(parent, "fd33:233:0:101::", status="network", desc="Network address"))
    await db_session.flush()
    result = await commit_subnet_split(db_session, parent, 65, confirm_cidr="fd33:233:0:101::/64")
    kids = (
        (await db_session.execute(select(Subnet).where(Subnet.block_id == block.id)))
        .scalars()
        .all()
    )
    assert len(kids) == 2
    for k in kids:
        rows = await _rows(db_session, k.id)
        assert rows.get(str(k.network).split("/")[0]) == "network", (k.network, rows)
    assert result is not None


@pytest.mark.asyncio
async def test_ipv6_split_host_on_child_network_is_refused(db_session):
    space, block = await _space_block(db_session, "fd33:233::/32")
    parent = await _subnet(db_session, space, block, "fd33:233:0:102::/64")
    db_session.add(_row(parent, "fd33:233:0:102:8000::"))
    await db_session.flush()
    preview = await preview_subnet_split(db_session, parent, 65)
    details = [c.detail for c in preview.conflicts if c.type == "host_on_child_boundary"]
    assert len(details) == 1 and "fd33:233:0:102:8000::" in details[0]
    with pytest.raises(SplitError) as exc:
        await commit_subnet_split(db_session, parent, 65, confirm_cidr="fd33:233:0:102::/64")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_ipv6_merge_keeps_network_row(db_session):
    space, block = await _space_block(db_session, "fd33:233::/32")
    a = await _subnet(db_session, space, block, "fd33:233:0:103::/65")
    b = await _subnet(db_session, space, block, "fd33:233:0:103:8000::/65")
    db_session.add(_row(a, "fd33:233:0:103::", status="network", desc="Network address"))
    db_session.add(_row(b, "fd33:233:0:103:8000::", status="network", desc="Network address"))
    await db_session.flush()
    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="fd33:233:0:103::/64")
    rows = await _rows(db_session, res.merged_subnet.id)
    assert rows == {"fd33:233:0:103::": "network"}


@pytest.mark.asyncio
async def test_resize_31_to_30_with_hosts_on_new_boundary_is_refused(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    s = await _subnet(db_session, space, block, "10.233.3.8/31")
    # grow target is 10.233.3.8/30: hosts at .8 (network) -> conflict
    db_session.add(_row(s, "10.233.3.8"))
    await db_session.flush()
    preview = await preview_subnet_resize(db_session, s, "10.233.3.8/30")
    assert any(
        c.type == "host_on_new_boundary" and "10.233.3.8" in c.detail for c in preview.conflicts
    )
    with pytest.raises(ResizeError) as exc:
        await commit_subnet_resize(db_session, s, "10.233.3.8/30")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_resize_ipv6_grow_creates_network_row(db_session):
    space, block = await _space_block(db_session, "fd33:233::/32")
    s = await _subnet(db_session, space, block, "fd33:233:0:5::/65")
    await commit_subnet_resize(db_session, s, "fd33:233:0:5::/64")
    assert (await _rows(db_session, s.id)).get("fd33:233:0:5::") == "network"


@pytest.mark.asyncio
async def test_block_resize_refusal_speaks_of_the_block(db_session):
    space, block = await _space_block(db_session, "10.233.16.0/22")
    preview = await preview_block_resize(db_session, block, "10.233.16.0/23")
    text = " ".join(c.detail for c in preview.conflicts)
    assert "reduce a block" in text and "reduce a subnet" not in text


@pytest.mark.asyncio
async def test_subnet_resize_refusal_still_speaks_of_the_subnet(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    s = await _subnet(db_session, space, block, "10.233.4.0/24")
    preview = await preview_subnet_resize(db_session, s, "10.233.4.0/25")
    assert "reduce a subnet" in " ".join(c.detail for c in preview.conflicts)


@pytest.mark.asyncio
async def test_split_children_keep_skip_reverse_zone(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    parent = await _subnet(db_session, space, block, "10.233.4.0/24", skip_reverse_zone=True)
    await commit_subnet_split(db_session, parent, 25, confirm_cidr="10.233.4.0/24")
    kids = (
        (await db_session.execute(select(Subnet).where(Subnet.block_id == block.id)))
        .scalars()
        .all()
    )
    assert len(kids) == 2 and all(k.skip_reverse_zone for k in kids)


@pytest.mark.asyncio
async def test_split_of_default_subnet_keeps_false(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    parent = await _subnet(db_session, space, block, "10.233.4.0/24")
    await commit_subnet_split(db_session, parent, 25, confirm_cidr="10.233.4.0/24")
    kids = (
        (await db_session.execute(select(Subnet).where(Subnet.block_id == block.id)))
        .scalars()
        .all()
    )
    assert not any(k.skip_reverse_zone for k in kids)


@pytest.mark.asyncio
async def test_merge_keeps_skip_reverse_zone_and_warns_on_disagreement(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    a = await _subnet(db_session, space, block, "10.233.6.0/25", skip_reverse_zone=True)
    b = await _subnet(db_session, space, block, "10.233.6.128/25", skip_reverse_zone=True)
    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.233.6.0/24")
    assert res.merged_subnet.skip_reverse_zone is True

    c = await _subnet(db_session, space, block, "10.233.7.0/25", skip_reverse_zone=True)
    d = await _subnet(db_session, space, block, "10.233.7.128/25")
    preview = await preview_subnet_merge(db_session, c, [d.id])
    assert any("skip_reverse_zone" in w for w in preview.warnings)


# ── Parity with create_subnet, end to end through the API ───────────────────
#
# The rule is only right if it is create's rule. Each row of the table is a
# subnet made by POST /ipam/subnets and the helper's answer for the same
# prefix: the network / broadcast rows must agree exactly.

PARITY_TABLE = [
    "10.240.0.0/16",
    "10.241.0.0/24",
    "10.241.1.0/29",
    "10.241.1.8/30",
    "10.241.1.12/31",
    "10.241.1.14/32",
    "fd40:1::/48",
    "fd40:2::/64",
    "fd40:2:0:1::/112",
    "fd40:2:0:2::/126",
    "fd40:2:0:3::/127",
    "fd40:2:0:4::1/128",
]


async def _api_tree(client: AsyncClient, db: AsyncSession):
    h = await _headers(db)
    space = IPSpace(name=f"sp2976-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    v4 = IPBlock(space_id=space.id, network="10.0.0.0/8", name="v4")
    v6 = IPBlock(space_id=space.id, network="fd40::/16", name="v6")
    db.add_all([v4, v6])
    await db.flush()
    await db.commit()
    return h, space, v4, v6


async def _api_create(client, h, space, v4, v6, cidr: str, **extra) -> str:
    block = v6 if ":" in cidr else v4
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": cidr,
            "skip_reverse_zone": True,
            **extra,
        },
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _api_rows(client, h, sid) -> dict[str, tuple[str, str | None]]:
    r = await client.get(f"/api/v1/ipam/subnets/{sid}/addresses", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    items = body["items"] if isinstance(body, dict) else body
    return {str(a["address"]): (a["status"], a.get("description")) for a in items}


def _boundary_only(rows: dict[str, tuple[str, str | None]]) -> dict[str, str]:
    return {a: st for a, (st, _d) in rows.items() if st in ("network", "broadcast")}


async def test_helper_matches_create_subnet_across_prefixes(
    client: AsyncClient, db_session: AsyncSession
):
    h, space, v4, v6 = await _api_tree(client, db_session)
    mismatches = []
    for cidr in PARITY_TABLE:
        sid = await _api_create(client, h, space, v4, v6, cidr)
        made = _boundary_only(await _api_rows(client, h, sid))
        net = ipaddress.ip_network(cidr, strict=False)
        want = {a: st for a, st, _d in boundary_rows(net)}
        if made != want:
            mismatches.append((cidr, made, want))
    assert mismatches == []


async def test_split_children_hold_what_create_holds_at_their_prefix(
    client: AsyncClient, db_session: AsyncSession
):
    h, space, v4, v6 = await _api_tree(client, db_session)
    for parent_cidr, prefix, kids, refs in (
        ("10.242.0.0/24", 25, ["10.242.0.0/25", "10.242.0.128/25"], "10.243.0.0/25"),
        ("10.242.1.0/29", 30, ["10.242.1.0/30", "10.242.1.4/30"], "10.243.1.0/30"),
        ("fd40:3::/64", 65, ["fd40:3::/65", "fd40:3:0:0:8000::/65"], "fd40:4::/65"),
        ("fd40:3:0:1::/125", 126, ["fd40:3:0:1::/126", "fd40:3:0:1::4/126"], "fd40:4:0:1::/126"),
    ):
        pid = await _api_create(client, h, space, v4, v6, parent_cidr)
        r = await client.post(
            f"/api/v1/ipam/subnets/{pid}/split/commit",
            headers=h,
            json={"new_prefix_length": prefix, "confirm_cidr": parent_cidr},
        )
        assert r.status_code == 200, r.text
        ref = _boundary_only(
            await _api_rows(client, h, await _api_create(client, h, space, v4, v6, refs))
        )
        ref_shape = sorted(ref.values())
        listing = (await client.get(f"/api/v1/ipam/subnets?space_id={space.id}", headers=h)).json()
        subs = listing["items"] if isinstance(listing, dict) else listing
        by_net = {s["network"]: s["id"] for s in subs}
        for kid in kids:
            got = _boundary_only(await _api_rows(client, h, by_net[kid]))
            assert sorted(got.values()) == ref_shape, (parent_cidr, kid, got, ref)


async def test_merge_result_holds_exactly_what_create_holds(
    client: AsyncClient, db_session: AsyncSession
):
    """Network, broadcast AND the one gateway create makes (#2976 IPv6 evidence)."""
    h, space, v4, v6 = await _api_tree(client, db_session)
    for a_cidr, b_cidr, merged, ref_cidr in (
        ("10.244.0.0/25", "10.244.0.128/25", "10.244.0.0/24", "10.245.0.0/24"),
        ("fd40:5::/65", "fd40:5:0:0:8000::/65", "fd40:5::/64", "fd40:6::/64"),
    ):
        a = await _api_create(client, h, space, v4, v6, a_cidr)
        b = await _api_create(client, h, space, v4, v6, b_cidr)
        pv = await client.post(
            f"/api/v1/ipam/subnets/{a}/merge/preview",
            headers=h,
            json={"sibling_subnet_ids": [b]},
        )
        assert pv.status_code == 200, pv.text
        assert any("retired" in w for w in pv.json()["warnings"]), pv.json()
        r = await client.post(
            f"/api/v1/ipam/subnets/{a}/merge/commit",
            headers=h,
            json={"sibling_subnet_ids": [b], "confirm_cidr": merged},
        )
        assert r.status_code == 200, r.text
        mid = r.json()["merged_subnet"]["id"]
        ref_id = await _api_create(client, h, space, v4, v6, ref_cidr)
        ref_rows = await _api_rows(client, h, ref_id)
        got_rows = await _api_rows(client, h, mid)

        def shape(rows, base):
            n = ipaddress.ip_network(base)
            return sorted(
                (int(ipaddress.ip_address(addr)) - int(n.network_address), st, d)
                for addr, (st, d) in rows.items()
            )

        assert shape(got_rows, merged) == shape(ref_rows, ref_cidr), (got_rows, ref_rows)
        sub = (await client.get(f"/api/v1/ipam/subnets/{mid}", headers=h)).json()
        ref = (await client.get(f"/api/v1/ipam/subnets/{ref_id}", headers=h)).json()
        assert int(ipaddress.ip_address(sub["gateway"])) - int(
            ipaddress.ip_network(merged).network_address
        ) == int(ipaddress.ip_address(ref["gateway"])) - int(
            ipaddress.ip_network(ref_cidr).network_address
        )


async def test_merge_keeps_an_edited_second_gateway(db_session):
    space, block = await _space_block(db_session, "10.246.0.0/16")
    a = await _subnet(db_session, space, block, "10.246.0.0/25", gateway="10.246.0.1")
    b = await _subnet(db_session, space, block, "10.246.0.128/25", gateway="10.246.0.129")
    db_session.add(_row(a, "10.246.0.1", status="reserved", desc="Gateway", host="gateway"))
    db_session.add(_row(b, "10.246.0.129", status="reserved", desc="Core router", host="gateway"))
    await db_session.flush()
    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.246.0.0/24")
    rows = await _rows(db_session, res.merged_subnet.id)
    assert str(res.merged_subnet.gateway) == "10.246.0.1"
    assert rows.get("10.246.0.129") == "reserved"


async def test_merge_with_no_create_gateway_keeps_both_and_clears_field(db_session):
    space, block = await _space_block(db_session, "10.247.0.0/16")
    a = await _subnet(db_session, space, block, "10.247.0.0/25", gateway="10.247.0.126")
    b = await _subnet(db_session, space, block, "10.247.0.128/25", gateway="10.247.0.129")
    db_session.add(_row(a, "10.247.0.126", status="reserved", desc="Gateway", host="gateway"))
    db_session.add(_row(b, "10.247.0.129", status="reserved", desc="Gateway", host="gateway"))
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert any("left empty" in w for w in preview.warnings)
    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.247.0.0/24")
    rows = await _rows(db_session, res.merged_subnet.id)
    assert res.merged_subnet.gateway is None
    assert rows.get("10.247.0.126") == rows.get("10.247.0.129") == "reserved"


# ── Existing data: refusals fire only on a boundary the operation creates ──


async def test_resize_keeping_network_address_tolerates_existing_host_there(db_session):
    """A host on the old network address (skip_auto_addresses / pre-#506 IPv6)."""
    space, block = await _space_block(db_session, "fd33:233::/32")
    s = await _subnet(db_session, space, block, "fd33:233:0:7::/65")
    db_session.add(_row(s, "fd33:233:0:7::", host="anycast"))
    await db_session.flush()
    preview = await preview_subnet_resize(db_session, s, "fd33:233:0:7::/64")
    assert not [c for c in preview.conflicts if c.type == "host_on_new_boundary"]
    await commit_subnet_resize(db_session, s, "fd33:233:0:7::/64")
    assert (await _rows(db_session, s.id))["fd33:233:0:7::"] == "allocated"


async def test_resize_moving_network_onto_a_host_is_refused(db_session):
    """An IPv6 /127 has no boundary; grown to a /126 its first address is one."""
    space, block = await _space_block(db_session, "fd33:233::/32")
    s4 = await _subnet(db_session, space, block, "fd33:233:0:a::/127")
    db_session.add(_row(s4, "fd33:233:0:a::"))
    await db_session.flush()
    preview = await preview_subnet_resize(db_session, s4, "fd33:233:0:a::/126")
    assert any(c.type == "host_on_new_boundary" for c in preview.conflicts)


async def test_merge_tolerates_host_already_on_its_source_network(db_session):
    space, block = await _space_block(db_session, "10.248.0.0/16")
    a = await _subnet(db_session, space, block, "10.248.0.0/25")  # skip_auto: no rows
    b = await _subnet(db_session, space, block, "10.248.0.128/25")
    db_session.add(_row(a, "10.248.0.0", host="legacy"))
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert not [c for c in preview.conflicts if c.type == "host_on_merged_boundary"]


async def test_split_tolerates_host_already_on_parent_network(db_session):
    space, block = await _space_block(db_session, "fd33:233::/32")
    parent = await _subnet(db_session, space, block, "fd33:233:0:b::/64")
    db_session.add(_row(parent, "fd33:233:0:b::", host="pre-506"))
    await db_session.flush()
    preview = await preview_subnet_split(db_session, parent, 65)
    assert not [c for c in preview.conflicts if c.type == "host_on_child_boundary"]


async def test_multicast_split_makes_no_boundary_rows_and_refuses_nothing(db_session):
    space, block = await _space_block(db_session, "239.1.0.0/16")
    parent = await _subnet(db_session, space, block, "239.1.2.0/24", kind="multicast")
    db_session.add(_row(parent, "239.1.2.128"))  # a stream, not a host
    await db_session.flush()
    preview = await preview_subnet_split(db_session, parent, 25)
    assert not [c for c in preview.conflicts if c.type == "host_on_child_boundary"]
    await commit_subnet_split(db_session, parent, 25, confirm_cidr="239.1.2.0/24")
    kids = (
        (await db_session.execute(select(Subnet).where(Subnet.block_id == block.id)))
        .scalars()
        .all()
    )
    for k in kids:
        assert set((await _rows(db_session, k.id)).values()) <= {"allocated"}
