"""A static root trust anchor is refused; a stored one renders as initial-key (#3609).

BIND 9.20 refuses ``dnssec-validation auto`` beside a ``static-key`` anchor
for ``.`` ("static trust anchor for root zone cannot be used with
'dnssec-validation auto'"), and in any mode warns that a static root anchor
"WILL FAIL after key rollover". The agent then declines the whole bundle and
the group stops converging.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions, DNSTrustAnchor
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.config_bundle import build_config_bundle as build_dataclass_bundle
from app.services.dns.server_move import ensure_group_single_driver
from tests.test_dns_trust_anchors_2266 import KEY, _anchor, _group, _superadmin


def _url(group: DNSServerGroup) -> str:
    return f"/api/v1/dns/groups/{group.id}/options"


async def _set_validation(
    client: AsyncClient, group: DNSServerGroup, value: str, headers: dict[str, str]
) -> None:
    r = await client.put(_url(group), json={"dnssec_validation": value}, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("validation", ["auto", "yes", "no"])
@pytest.mark.parametrize("zone_name", [".", ""])
async def test_static_root_anchor_is_422_in_every_mode(
    client: AsyncClient, db_session: AsyncSession, validation: str, zone_name: str
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    if validation == "yes":
        # ``yes`` needs an anchor first (#3560); add a non-root one.
        r = await client.post(
            f"{_url(group)}/trust-anchors",
            json=_anchor(zone_name="example.com", is_initial_key=False),
            headers=headers,
        )
        assert r.status_code == 201, r.text
    await _set_validation(client, group, validation, headers)

    r = await client.post(
        f"{_url(group)}/trust-anchors",
        json=_anchor(zone_name=zone_name, is_initial_key=False),
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert "initial-key" in r.text and "rollover" in r.text


@pytest.mark.asyncio
async def test_static_root_anchor_is_422_on_an_empty_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, None)
    await db_session.commit()
    r = await client.post(
        f"{_url(group)}/trust-anchors", json=_anchor(is_initial_key=False), headers=headers
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("validation", ["auto", "yes"])
async def test_initial_key_root_anchor_is_accepted_under_auto_and_yes(
    client: AsyncClient, db_session: AsyncSession, validation: str
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.post(f"{_url(group)}/trust-anchors", json=_anchor(), headers=headers)
    assert r.status_code == 201, r.text
    assert r.json()["is_initial_key"] is True
    await _set_validation(client, group, validation, headers)
    r = await client.get(_url(group), headers=headers)
    assert r.json()["dnssec_warnings"] == []


@pytest.mark.asyncio
async def test_root_anchor_defaults_to_initial_key(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    body = _anchor()
    body.pop("is_initial_key")
    r = await client.post(f"{_url(group)}/trust-anchors", json=body, headers=headers)
    assert r.status_code == 201, r.text
    assert r.json()["is_initial_key"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("validation", ["auto", "yes"])
async def test_static_anchor_for_a_non_root_zone_is_still_accepted(
    client: AsyncClient, db_session: AsyncSession, validation: str
) -> None:
    headers = await _superadmin(db_session)
    group, server = await _group(db_session, "bind9")
    await db_session.commit()
    assert server is not None
    sid = server.id
    r = await client.post(
        f"{_url(group)}/trust-anchors",
        json=_anchor(zone_name="corp.example.com", is_initial_key=False),
        headers=headers,
    )
    assert r.status_code == 201, r.text
    await _set_validation(client, group, validation, headers)

    db_session.expire_all()
    server = await db_session.get(DNSServer, sid)
    assert server is not None
    bundle = await build_config_bundle(db_session, server)
    assert bundle["options"]["trust_anchors"][0]["is_initial_key"] is False


async def _legacy_static_root(
    db: AsyncSession, validation: str
) -> tuple[DNSServerGroup, DNSServer]:
    """A group stored before #3609 refused a static root anchor."""
    group, server = await _group(db, "bind9")
    opts = DNSServerOptions(group_id=group.id, dnssec_validation=validation)
    db.add(opts)
    await db.flush()
    db.add(
        DNSTrustAnchor(
            server_options_id=opts.id,
            zone_name=".",
            algorithm=8,
            key_tag=20326,
            public_key=KEY,
            is_initial_key=False,
            added_at=datetime.now(UTC),
        )
    )
    await db.commit()
    assert server is not None
    return group, server


@pytest.mark.asyncio
@pytest.mark.parametrize("validation", ["auto", "yes"])
async def test_stored_static_root_anchor_renders_as_initial_key_and_is_reported(
    client: AsyncClient, db_session: AsyncSession, validation: str
) -> None:
    headers = await _superadmin(db_session)
    group, server = await _legacy_static_root(db_session, validation)
    sid = server.id

    bundle = await build_config_bundle(db_session, server)
    assert bundle["options"]["dnssec_validation"] == validation
    assert [a["is_initial_key"] for a in bundle["options"]["trust_anchors"]] == [True]

    db_session.expire_all()
    server = await db_session.get(DNSServer, sid)
    assert server is not None
    dataclass_bundle = await build_dataclass_bundle(db_session, server)
    assert [a.is_initial_key for a in dataclass_bundle.options.trust_anchors] == [True]

    r = await client.get(_url(group), headers=headers)
    # The stored row is reported as it is, with a warning on what is rendered.
    assert [a["is_initial_key"] for a in r.json()["trust_anchors"]] == [False]
    assert any("rendered as initial-key" in w for w in r.json()["dnssec_warnings"])


@pytest.mark.asyncio
async def test_stored_static_root_anchor_does_not_block_auto_or_joining(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """With the fallback the group's config loads under ``auto``, so switching
    to it and a BIND9 server joining stay allowed."""
    headers = await _superadmin(db_session)
    group, _ = await _legacy_static_root(db_session, "yes")
    await _set_validation(client, group, "auto", headers)
    await ensure_group_single_driver(db_session, group.id, "bind9", group_name="g", hint="")
