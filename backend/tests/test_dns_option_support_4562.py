"""#4562: one table of which group options each DNS driver applies.

The guard half fails when an options column, a relevant group field or a
registered driver has no decision in ``option_support``; the API half checks
that a change to an option the group's driver does not apply is a 422, while
an untouched Save and turning an option off keep working.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns import _DRIVERS
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions
from app.services.dns import option_support as table
from app.services.dns.technitium_options import UNSUPPORTED_OPTIONS

_COLUMNS = [
    c.key
    for c in DNSServerOptions.__table__.columns
    if c.key not in ("id", "group_id", "created_at", "modified_at")
]

# ── guard ───────────────────────────────────────────────────────────────────


def test_every_option_and_driver_pair_has_a_decision() -> None:
    missing = [
        f"{driver}.{field}"
        for driver in sorted(_DRIVERS)
        for field in (*_COLUMNS, "is_recursive")
        if table.OPTION_SUPPORT.get(driver, {}).get(field) is None
    ]
    assert not missing, f"no decision in option_support.OPTION_SUPPORT for: {missing}"
    states = {e.state for column in table.OPTION_SUPPORT.values() for e in column.values()}
    assert states <= {table.APPLIED, table.PARTIAL, table.NOT_APPLIED}


def test_table_names_only_real_drivers_and_fields() -> None:
    # A typo in the table would decide nothing and leave the real field
    # "applied" by omission.
    assert set(table.OPTION_SUPPORT) == set(_DRIVERS)
    assert set(table.DRIVER_LABELS) == set(_DRIVERS)
    assert table.DECLARED_FIELDS <= {*_COLUMNS, "is_recursive"}
    assert set(table.OPTION_FIELDS) == set(_COLUMNS)


def test_not_applied_and_partial_carry_a_note() -> None:
    for driver, column in table.OPTION_SUPPORT.items():
        for field, entry in column.items():
            if entry.state != table.APPLIED:
                assert entry.note, f"{driver}.{field} has no note"


def test_technitium_defaults_match_the_column_defaults() -> None:
    # The page and the generic gate read "inert" from this dict's defaults.
    for field, (default, _why) in UNSUPPORTED_OPTIONS.items():
        assert table.column_default(field) == default, field


def test_fresh_defaults_are_never_refused() -> None:
    # The form posts every field on every save: a group holding only column
    # defaults (recursion on among them) must pass on every driver.
    defaults = {f: table.column_default(f) for f in _COLUMNS}
    stored = type("Row", (), defaults)()
    for driver in _DRIVERS:
        assert table.refusals(driver, dict(defaults), stored) == [], driver


def test_known_cells() -> None:
    assert table.support("powerdns", "recursion_enabled").state == table.NOT_APPLIED
    assert table.support("powerdns", "forwarders").state == table.PARTIAL
    assert table.support("powerdns", "dnsdist_enabled").state == table.APPLIED
    assert table.support("bind9", "dnsdist_enabled").state == table.NOT_APPLIED
    assert table.support("bind9", "allow_recursion").state == table.APPLIED
    assert table.support("technitium", "query_log_enabled").state == table.NOT_APPLIED
    assert table.support("technitium", "allow_recursion").state == table.APPLIED
    for driver in ("windows_dns", "route53", "technitium_api"):
        assert table.applies_no_option(driver)
        assert all(e.state == table.NOT_APPLIED for e in table.OPTION_SUPPORT[driver].values())


# ── API ─────────────────────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Superadmin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession, driver: str | None) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db.add(group)
    await db.flush()
    if driver:
        db.add(
            DNSServer(
                group_id=group.id,
                name=f"s-{uuid.uuid4().hex[:8]}",
                driver=driver,
                host="192.0.2.10",
            )
        )
        await db.flush()
    await db.commit()
    return group


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("driver", "body", "named"),
    [
        ("powerdns", {"allow_query": ["10.0.0.0/8"]}, "PowerDNS"),
        ("powerdns", {"rrl_enabled": True}, "PowerDNS"),
        ("powerdns", {"dnssec_validation": "no"}, "PowerDNS"),
        ("powerdns", {"minimal_responses": True}, "PowerDNS"),
        ("powerdns", {"forward_policy": "only"}, "PowerDNS"),
        ("bind9", {"dnsdist_enabled": True}, "BIND9"),
        ("technitium", {"query_log_enabled": True}, "Technitium"),
        ("technitium", {"rrl_log_only": True}, "Technitium"),
        ("windows_dns", {"forwarders": ["1.1.1.1"]}, "Windows DNS"),
        ("windows_dns", {"blackhole": ["10.9.9.9"]}, "Windows DNS"),
        ("windows_dns", {"recursion_enabled": False}, "Windows DNS"),
        ("route53", {"allow_query": ["10.0.0.0/8"]}, "Route 53"),
        ("cloudflare", {"rrl_enabled": True}, "Cloudflare"),
    ],
)
async def test_change_to_an_unapplied_option_is_refused(
    client: AsyncClient,
    db_session: AsyncSession,
    driver: str,
    body: dict,
    named: str,
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, driver)
    r = await client.put(f"/api/v1/dns/groups/{group.id}/options", json=body, headers=headers)
    assert r.status_code == 422, r.text
    detail = str(r.json()["detail"])
    assert next(iter(body)) in detail
    assert named in detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "driver", ["bind9", "powerdns", "technitium", "windows_dns", "route53", None]
)
async def test_untouched_save_of_a_fresh_group_passes(
    client: AsyncClient, db_session: AsyncSession, driver: str | None
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, driver)
    url = f"/api/v1/dns/groups/{group.id}/options"
    stored = (await client.get(url, headers=headers)).json()
    body = {f: stored[f] for f in _COLUMNS if f != "tls_certificate_id" and f in stored}
    r = await client.put(url, json=body, headers=headers)
    assert r.status_code == 200, r.text
    # And again over the row the first save created.
    r = await client.put(url, json=body, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_applied_and_partial_options_still_save(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    pdns = await _group(db_session, "powerdns")
    r = await client.put(
        f"/api/v1/dns/groups/{pdns.id}/options",
        json={"forwarders": ["1.1.1.1"], "dnsdist_enabled": True, "also_notify": ["192.0.2.5"]},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    empty = await _group(db_session, None)
    r = await client.put(
        f"/api/v1/dns/groups/{empty.id}/options", json={"dnsdist_enabled": True}, headers=headers
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_stored_value_can_be_cleared_and_is_warned_about(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, "powerdns")
    db_session.add(DNSServerOptions(group_id=group.id, allow_query=["10.0.0.0/8"]))
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    got = (await client.get(url, headers=headers)).json()
    assert any("allow_query" in w and "PowerDNS" in w for w in got["unapplied_warnings"])
    assert got["option_support"]["allow_query"]["locked"] is False
    # Re-saving the stored value passes; so does clearing it.
    r = await client.put(url, json={"allow_query": ["10.0.0.0/8"]}, headers=headers)
    assert r.status_code == 200, r.text
    r = await client.put(url, json={"allow_query": ["any"]}, headers=headers)
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["unapplied_warnings"] == []
    assert got["option_support"]["allow_query"]["locked"] is True


@pytest.mark.asyncio
async def test_options_response_carries_the_groups_slice(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    pdns = await _group(db_session, "powerdns")
    got = (await client.get(f"/api/v1/dns/groups/{pdns.id}/options", headers=headers)).json()
    sup = got["option_support"]
    assert got["options_unmanaged_note"] is None
    assert sup["forwarders"]["state"] == "partial"
    assert sup["allow_recursion"] == {
        "state": "not_applied",
        "drivers": ["PowerDNS"],
        "note": table.support("powerdns", "allow_recursion").note,
        "locked": True,
    }
    # Stored on (the column default): editable, so it can be turned off.
    assert sup["recursion_enabled"]["locked"] is False
    assert "dnsdist_enabled" not in sup
    # Nothing to warn about on a fresh group.
    assert got["unapplied_warnings"] == []

    win = await _group(db_session, "windows_dns")
    got = (await client.get(f"/api/v1/dns/groups/{win.id}/options", headers=headers)).json()
    assert "Windows DNS" in got["options_unmanaged_note"]

    bind = await _group(db_session, "bind9")
    got = (await client.get(f"/api/v1/dns/groups/{bind.id}/options", headers=headers)).json()
    assert got["options_unmanaged_note"] is None
    assert got["option_support"]["dnsdist_enabled"]["locked"] is True
    assert "recursion_enabled" not in got["option_support"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("driver", "turn_off", "turn_on"),
    [
        # The agentless servers keep whatever recursion they have: no change is true.
        ("technitium_api", 422, 422),
        ("windows_dns", 422, 422),
        # Never recurses: "off" is true, "on" is not.
        ("powerdns", 200, 422),
        ("route53", 200, 422),
        ("bind9", 200, 200),
        ("technitium", 200, 200),
    ],
)
async def test_group_is_recursive_follows_the_table(
    client: AsyncClient, db_session: AsyncSession, driver: str, turn_off: int, turn_on: int
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, driver)
    url = f"/api/v1/dns/groups/{group.id}"
    assert group.is_recursive is True
    # Untouched.
    r = await client.put(url, json={"is_recursive": True}, headers=headers)
    assert r.status_code == 200, r.text
    assert ("is_recursive" in r.json()["unapplied_fields"]) == (turn_on == 422)
    r = await client.put(url, json={"is_recursive": False}, headers=headers)
    assert r.status_code == turn_off, r.text
    if turn_off == 422:
        assert "is_recursive" in str(r.json()["detail"])
        return
    r = await client.put(url, json={"is_recursive": True}, headers=headers)
    assert r.status_code == turn_on, r.text
