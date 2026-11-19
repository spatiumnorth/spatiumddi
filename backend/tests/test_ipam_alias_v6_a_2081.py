"""An ``A`` alias on an IPv6 address is stored as AAAA on every path (#2081).

``_create_alias_records`` turns an alias of type ``A`` into an ``AAAA`` on an
IPv6 address. ``POST /addresses/{id}/aliases`` then looked the new row up by
the REQUESTED type, found nothing, answered 409 and rolled the write back, so
an A alias could never be added to an IPv6 address there. Allocate and next-IP
never did that lookup and always worked; all three are pinned here, with an
IPv4 control. ``AAAA`` is not an accepted alias type at all (``AliasInput``
422s it), so there is no AAAA-on-IPv4 case to disagree about.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_ipam_alias_cname_exclusive_2080 import _alloc, _records, _setup


@pytest.mark.asyncio
async def test_a_alias_on_ipv6_is_stored_as_aaaa_on_all_three_paths(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(
        client, db_session, block_cidr="fd20:81::/48", subnet_cidr="fd20:81:0:1::/64"
    )

    # allocate
    r1 = await _alloc(
        client,
        headers,
        sid,
        "fd20:81:0:1::10",
        "h1",
        aliases=[{"name": "a1", "record_type": "A"}],
    )
    assert r1.status_code == 201, r1.text

    # next-IP
    r2 = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "h2", "aliases": [{"name": "a2", "record_type": "A"}]},
    )
    assert r2.status_code == 201, r2.text

    # add-alias on an existing address
    r3 = await _alloc(client, headers, sid, "fd20:81:0:1::30", "h3")
    assert r3.status_code == 201, r3.text
    add = await client.post(
        f"/api/v1/ipam/addresses/{r3.json()['id']}/aliases",
        headers=headers,
        json={"name": "a3", "record_type": "A"},
    )
    assert add.status_code == 201, add.text
    body = add.json()
    assert body["record_type"] == "AAAA"
    assert body["value"] == "fd20:81:0:1::30"

    recs = await _records(db_session, zone.id)
    for alias in ("a1", "a2", "a3"):
        assert (alias, "AAAA") in recs
        assert (alias, "A") not in recs

    # the alias is served: listed on the address
    listed = await client.get(f"/api/v1/ipam/addresses/{r3.json()['id']}/aliases", headers=headers)
    assert listed.status_code == 200, listed.text
    assert [(a["name"], a["record_type"]) for a in listed.json()] == [("a3", "AAAA")]
    # ...and in the subnet-wide listing, primaries still excluded
    sub = await client.get(f"/api/v1/ipam/subnets/{sid}/aliases", headers=headers)
    assert sub.status_code == 200, sub.text
    assert sorted(a["name"] for a in sub.json()) == ["a1", "a2", "a3"]


@pytest.mark.asyncio
async def test_a_alias_on_ipv4_stays_a_on_all_three_paths(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    r1 = await _alloc(
        client, headers, sid, "10.98.5.10", "h1", aliases=[{"name": "a1", "record_type": "A"}]
    )
    assert r1.status_code == 201, r1.text
    r2 = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "h2", "aliases": [{"name": "a2", "record_type": "A"}]},
    )
    assert r2.status_code == 201, r2.text
    r3 = await _alloc(client, headers, sid, "10.98.5.30", "h3")
    add = await client.post(
        f"/api/v1/ipam/addresses/{r3.json()['id']}/aliases",
        headers=headers,
        json={"name": "a3", "record_type": "A"},
    )
    assert add.status_code == 201, add.text
    assert add.json()["record_type"] == "A"
    recs = await _records(db_session, zone.id)
    for alias in ("a1", "a2", "a3"):
        assert (alias, "A") in recs
        assert (alias, "AAAA") not in recs


@pytest.mark.asyncio
async def test_aaaa_alias_type_is_refused_at_the_door(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    r = await _alloc(client, headers, sid, "10.98.5.40", "h4")
    add = await client.post(
        f"/api/v1/ipam/addresses/{r.json()['id']}/aliases",
        headers=headers,
        json={"name": "x", "record_type": "AAAA"},
    )
    assert add.status_code == 422, add.text
