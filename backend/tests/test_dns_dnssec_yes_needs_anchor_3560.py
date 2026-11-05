"""``dnssec_validation = yes`` with no trust anchor is refused on BIND9 (#3560).

BIND 9.20 will not load ``dnssec-validation yes`` without ``trust-anchors``;
the agent then declines the whole bundle and the group stops converging.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions
from app.models.settings import PlatformSettings
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.new_object_defaults import load_dns_defaults
from app.services.dns.server_move import ServerMoveError, ensure_group_single_driver
from tests.test_dns_trust_anchors_2266 import _anchor, _group, _superadmin


def _url(group: DNSServerGroup) -> str:
    return f"/api/v1/dns/groups/{group.id}/options"


@pytest.mark.asyncio
async def test_yes_without_anchor_is_422_naming_both_fixes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.put(_url(group), json={"dnssec_validation": "yes"}, headers=headers)
    assert r.status_code == 422, r.text
    assert "'auto'" in r.text and "trust anchor" in r.text


@pytest.mark.asyncio
async def test_empty_group_reads_as_bind9(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, None)
    await db_session.commit()
    r = await client.put(_url(group), json={"dnssec_validation": "yes"}, headers=headers)
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["auto", "no"])
async def test_auto_and_no_are_accepted(
    client: AsyncClient, db_session: AsyncSession, value: str
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.put(_url(group), json={"dnssec_validation": value}, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_yes_with_anchor_is_accepted(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.post(f"{_url(group)}/trust-anchors", json=_anchor(), headers=headers)
    assert r.status_code == 201, r.text
    r = await client.put(_url(group), json={"dnssec_validation": "yes"}, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["technitium", "powerdns"])
async def test_other_drivers_still_accept_yes(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, driver)
    await db_session.commit()
    r = await client.put(_url(group), json={"dnssec_validation": "yes"}, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_deleting_the_last_anchor_under_yes_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    await db_session.commit()
    a1 = await client.post(f"{_url(group)}/trust-anchors", json=_anchor(), headers=headers)
    a2 = await client.post(
        f"{_url(group)}/trust-anchors", json=_anchor(key_tag=20327), headers=headers
    )
    assert a1.status_code == a2.status_code == 201
    r = await client.put(_url(group), json={"dnssec_validation": "yes"}, headers=headers)
    assert r.status_code == 200, r.text

    r = await client.delete(f"{_url(group)}/trust-anchors/{a1.json()['id']}", headers=headers)
    assert r.status_code == 204, r.text  # one remains
    r = await client.delete(f"{_url(group)}/trust-anchors/{a2.json()['id']}", headers=headers)
    assert r.status_code == 422, r.text
    assert "'auto'" in r.text

    # Switching to auto first lets it go.
    r = await client.put(_url(group), json={"dnssec_validation": "auto"}, headers=headers)
    assert r.status_code == 200
    r = await client.delete(f"{_url(group)}/trust-anchors/{a2.json()['id']}", headers=headers)
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
async def test_bind9_server_cannot_join_a_yes_group_without_anchor(
    db_session: AsyncSession,
) -> None:
    empty, _ = await _group(db_session, None)
    db_session.add(DNSServerOptions(group_id=empty.id, dnssec_validation="yes"))
    await db_session.flush()
    with pytest.raises(ServerMoveError) as exc:
        await ensure_group_single_driver(db_session, empty.id, "bind9", group_name="g", hint="")
    assert exc.value.status_code == 422
    assert "'auto'" in str(exc.value)
    # ...and a non-BIND9 one may.
    await ensure_group_single_driver(db_session, empty.id, "technitium", group_name="g", hint="")


@pytest.mark.asyncio
async def test_server_create_into_yes_group_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, None)
    db_session.add(DNSServerOptions(group_id=group.id, dnssec_validation="yes"))
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers",
        json={"name": "ns1", "driver": "bind9", "host": "ns1.example.com"},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert "'auto'" in r.text


@pytest.mark.asyncio
async def test_settings_default_of_yes_is_refused_and_stored_yes_degrades(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    r = await client.put(
        "/api/v1/settings", json={"dns_default_dnssec_validation": "yes"}, headers=headers
    )
    assert r.status_code == 422, r.text

    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.dns_default_dnssec_validation = "yes"
    await db_session.commit()
    assert (await load_dns_defaults(db_session)).dnssec_validation == "auto"


@pytest.mark.asyncio
async def test_existing_yes_row_renders_auto_and_is_reported(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A row stored before the refusal must not stop the group converging."""
    headers = await _superadmin(db_session)
    group, server = await _group(db_session, "bind9")
    db_session.add(DNSServerOptions(group_id=group.id, dnssec_validation="yes"))
    await db_session.commit()
    assert server is not None
    sid = server.id

    bundle = await build_config_bundle(db_session, server)
    assert bundle["options"]["dnssec_validation"] == "auto"

    r = await client.get(_url(group), headers=headers)
    assert r.json()["dnssec_validation"] == "yes"
    assert any("rendered as 'auto'" in w for w in r.json()["dnssec_warnings"])

    # With an anchor the stored value is honoured.
    r = await client.post(f"{_url(group)}/trust-anchors", json=_anchor(), headers=headers)
    assert r.status_code == 201
    db_session.expire_all()
    server = await db_session.get(DNSServer, sid)
    assert server is not None
    bundle = await build_config_bundle(db_session, server)
    assert bundle["options"]["dnssec_validation"] == "yes"


@pytest.mark.asyncio
async def test_existing_yes_row_still_saves_other_options(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The Options tab re-sends every field on save, ``dnssec_validation``
    included; a group stored at ``yes`` before the refusal must still be able
    to change anything else (the check is on the transition to ``yes``)."""
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "bind9")
    db_session.add(DNSServerOptions(group_id=group.id, dnssec_validation="yes"))
    await db_session.commit()
    r = await client.put(
        _url(group),
        json={"dnssec_validation": "yes", "minimal_responses": True},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["minimal_responses"] is True


@pytest.mark.asyncio
async def test_driver_bundle_also_renders_auto_for_existing_yes_row(
    db_session: AsyncSession,
) -> None:
    """The dataclass ``ConfigBundle`` (control-plane BIND9 driver) applies the
    same fallback as the agent wire bundle, so the two cannot disagree."""
    from app.services.dns.config_bundle import build_config_bundle as build_dataclass_bundle

    group, server = await _group(db_session, "bind9")
    db_session.add(DNSServerOptions(group_id=group.id, dnssec_validation="yes"))
    await db_session.commit()
    assert server is not None
    bundle = await build_dataclass_bundle(db_session, server)
    assert bundle.options.dnssec_validation == "auto"
