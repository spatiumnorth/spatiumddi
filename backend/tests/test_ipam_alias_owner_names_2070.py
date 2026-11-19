"""spatiumddi#2070 — an IPAM alias follows the DNS record API's owner-name rule.

``under_score`` as an A alias was stored and written into the zone, where
BIND's check-names refuses it and the agent holds the zone's whole config.
The alias input now runs the same checks the DNS record API does
(``validate_record_owner`` + ``bind_check_names_error``).
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import AliasInput
from app.core.dns_names import bind_check_names_error
from tests.test_ipam_forward_zone_type_1633 import (
    _allocate,
    _headers,
    _records,
    _setup,
    _subnet,
    _zone,
)


def test_alias_schema_matches_the_dns_record_api_rule() -> None:
    for rtype in ("A", "AAAA"):
        assert bind_check_names_error(rtype, "under_score", None, origin="z.") is not None
    with pytest.raises(ValueError, match="under_score"):
        AliasInput(name="under_score", record_type="A")
    # Allowed where the DNS API allows it: a CNAME owner is not host-checked.
    assert AliasInput(name="under_score", record_type="CNAME").name == "under_score"
    assert AliasInput(name="www", record_type="A").name == "www"
    with pytest.raises(ValueError, match="bad name"):
        AliasInput(name="bad name", record_type="CNAME")


@pytest.mark.asyncio
async def test_alias_endpoints_422_a_bad_a_alias_and_write_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp, space, block = await _setup(db_session)
    zone = _zone(grp, "corp", "primary")
    db_session.add(zone)
    await db_session.commit()
    sid = await _subnet(client, headers, space, block, grp, zone)

    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={
            "address": "10.97.5.10",
            "hostname": "host",
            "aliases": [{"name": "under_score", "record_type": "A"}],
        },
    )
    assert resp.status_code == 422, resp.text
    assert "under_score" in resp.text

    host = await _allocate(client, headers, sid, "10.97.5.11", "host2")
    resp = await client.post(
        f"/api/v1/ipam/addresses/{host}/aliases",
        headers=headers,
        json={"name": "under_score", "record_type": "A"},
    )
    assert resp.status_code == 422, resp.text
    assert "under_score" in resp.text
    names = {r[0] for r in await _records(db_session, zone.id)}
    assert "under_score" not in names

    # A legal alias, and an underscore CNAME (legal in the DNS API), still work.
    for body in ({"name": "www", "record_type": "A"}, {"name": "_svc", "record_type": "CNAME"}):
        ok = await client.post(f"/api/v1/ipam/addresses/{host}/aliases", headers=headers, json=body)
        assert ok.status_code == 201, ok.text


def test_alias_name_is_stored_in_the_form_the_checks_passed() -> None:
    # An internationalized A alias passes as its A-label; storing the raw
    # form would put non-LDH bytes in the zone, which check-names refuses.
    assert AliasInput(name="Café", record_type="A").name == "xn--caf-dma"
    assert AliasInput(name="WWW", record_type="A").name == "www"
    # One message naming the alias, not the alias named twice.
    with pytest.raises(ValidationError) as exc:
        AliasInput(name="a..b", record_type="CNAME")
    assert exc.value.errors()[0]["msg"].count("a..b") == 1


@pytest.mark.asyncio
async def test_alias_too_long_inside_its_zone_is_422_on_every_path(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Four 60-character labels are a legal name alone (243 characters), and
    over 253 once the zone is appended — the length BIND refuses the zone at."""
    headers = await _headers(db_session)
    grp, space, block = await _setup(db_session)
    zone = _zone(grp, "corp", "primary")
    db_session.add(zone)
    await db_session.commit()
    sid = await _subnet(client, headers, space, block, grp, zone)
    long_alias = ".".join(c * 60 for c in "abcd")
    alias = [{"name": long_alias, "record_type": "CNAME"}]

    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.97.5.20", "hostname": "h20", "aliases": alias},
    )
    assert resp.status_code == 422, resp.text
    assert "253" in resp.text

    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "h21", "aliases": alias},
    )
    assert resp.status_code == 422, resp.text

    host = await _allocate(client, headers, sid, "10.97.5.22", "h22")
    resp = await client.post(
        f"/api/v1/ipam/addresses/{host}/aliases", headers=headers, json=alias[0]
    )
    assert resp.status_code == 422, resp.text

    names = {r[0] for r in await _records(db_session, zone.id)}
    assert names == {"h22"}, names
