"""Technitium zone transfer: the API refuses what the agent cannot translate,
and a secondary's bundle names the key its master requires (#1765)."""

from __future__ import annotations

import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSAcl,
    DNSAclEntry,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSTSIGKey,
    DNSZone,
)
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.technitium_options import (
    AddressMatchError,
    allow_transfer_problem,
    refusals,
    stored_warnings,
    translate_address_match,
)

# ── the translator ───────────────────────────────────────────────────────


def test_a_negation_beside_any_keeps_its_exclusion() -> None:
    acl, keys = translate_address_match(["!10.1.0.0/16", "any"], allow_keys=True)
    assert acl == ["!10.1.0.0/16", "0.0.0.0/0", "::/0"]
    assert keys == []


def test_keys_and_exclusions_combine_only_in_the_exact_order() -> None:
    assert translate_address_match(["!10.1.0.0/16", "key k"], allow_keys=True) == (
        ["!10.1.0.0/16", "0.0.0.0/0", "::/0"],
        ["k"],
    )
    for bad in (["10.0.0.0/8", "key k"], ["key k", "!10.1.0.0/16"], ["!key k"]):
        with pytest.raises(AddressMatchError):
            translate_address_match(bad, allow_keys=True)


def test_none_is_bind_s_deny_all_not_a_no_op() -> None:
    """BIND compiles ``none`` as ``!any`` (aclconf.c): ``["none", "10/8"]``
    admits nobody. Dropping ``none`` would grant 10/8 (#1765 validation)."""
    assert translate_address_match(["none", "10.0.0.0/8"]) == (["!0.0.0.0/0", "!::/0"], [])
    assert translate_address_match(["!none"]) == (["0.0.0.0/0", "::/0"], [])
    # Nothing after ``none`` is reachable, a key included.
    assert translate_address_match(["none", "key k"], allow_keys=True) == (
        ["!0.0.0.0/0", "!::/0"],
        [],
    )
    assert translate_address_match(["key k", "none"], allow_keys=True) == (
        ["0.0.0.0/0", "::/0"],
        ["k"],
    )
    # An ACL holding ``none`` denies from that point too.
    assert translate_address_match(["a", "10.0.0.0/8"], {"a": [("none", False)]}) == (
        ["!0.0.0.0/0", "!::/0"],
        [],
    )


def test_an_ipv4_mapped_prefix_is_refused() -> None:
    with pytest.raises(AddressMatchError):
        translate_address_match(["!::ffff:10.1.0.0/112", "any"])


def test_a_key_is_not_a_query_acl_element() -> None:
    with pytest.raises(AddressMatchError):
        translate_address_match(["key k"], allow_keys=False)


def test_named_acls_are_expanded_and_cycles_refused() -> None:
    acls = {
        "a": [("10.0.0.0/8", False), ("b", False)],
        "b": [("192.0.2.0/24", False)],
        "loop": [("loop", False)],
    }
    assert translate_address_match(["a"], acls)[0] == ["10.0.0.0/8", "192.0.2.0/24"]
    assert translate_address_match(["!a"], acls)[0] == ["!10.0.0.0/8", "!192.0.2.0/24"]
    with pytest.raises(AddressMatchError):
        translate_address_match(["loop"], acls)


def test_nothing_is_ever_widened_by_an_inexact_translation() -> None:
    # The server's own addresses are more than loopback, so negating it would
    # drop an exclusion; localnets has no equivalent at all.
    for bad in (["!localhost", "any"], ["localnets"], ["nope"]):
        with pytest.raises(AddressMatchError):
            translate_address_match(bad)


def test_the_gate_reports_a_problem_and_passes_a_clean_list() -> None:
    assert allow_transfer_problem(["!10.1.0.0/16", "any"]) is None
    assert allow_transfer_problem(["key xfer"]) is None
    assert "localnets" in (allow_transfer_problem(["localnets"]) or "")


def test_a_changed_transfer_list_is_refused_and_an_unchanged_one_is_not() -> None:
    class Stored:
        allow_transfer = ["localnets"]

    assert refusals({"allow_transfer": ["localnets"]}, Stored()) == []
    assert refusals({"allow_transfer": ["localhost", "localnets"]}, Stored())
    assert any("allow_transfer" in w for w in stored_warnings(Stored()))


# ── the API ──────────────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession, driver: str) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(
        DNSServer(
            group_id=group.id,
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver=driver,
            host=f"h-{uuid.uuid4().hex[:6]}",
            port=53,
        )
    )
    await db.flush()
    return group


@pytest.mark.asyncio
async def test_group_allow_transfer_the_daemon_cannot_apply_is_a_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, "technitium")
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    r = await client.put(url, json={"allow_transfer": ["localnets"]}, headers=headers)
    assert r.status_code == 422, r.text
    assert "allow_transfer" in str(r.json()["detail"])
    # What it can express is accepted, exclusions and all.
    r = await client.put(url, json={"allow_transfer": ["!10.1.0.0/16", "any"]}, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_a_defined_acl_is_accepted_for_transfer_and_query(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, "technitium")
    acl = DNSAcl(group_id=group.id, name="office")
    acl.entries = [DNSAclEntry(value="10.0.0.0/8", negate=False, order=0)]
    db_session.add(acl)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"allow_transfer": ["office"], "allow_query": ["office"]},
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_a_bind_group_keeps_localnets(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"allow_transfer": ["localnets"]},
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_zone_allow_transfer_is_gated_and_stored_values_are_warned(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session, "technitium")
    db_session.add(DNSServerOptions(group_id=group.id))
    stored = DNSZone(
        group_id=group.id,
        name="old.test.",
        zone_type="primary",
        kind="forward",
        allow_transfer=["localnets"],
    )
    db_session.add(stored)
    await db_session.commit()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json={"name": "new.test.", "zone_type": "primary", "allow_transfer": ["localnets"]},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json={
            "name": "new.test.",
            "zone_type": "primary",
            "allow_transfer": ["!10.1.0.0/16", "any"],
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text

    r = await client.get(f"/api/v1/dns/groups/{group.id}/options", headers=headers)
    warnings = r.json()["technitium_warnings"]
    assert any("old.test." in w and "allow_transfer" in w for w in warnings), warnings


# ── the bundle ───────────────────────────────────────────────────────────


async def _agent_server(
    db: AsyncSession, driver: str, host: str, secret: str
) -> tuple[DNSServerGroup, DNSServer]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    group.tsig_key_name = f"spatium-{uuid.uuid4().hex[:6]}"
    group.tsig_key_secret_encrypted = encrypt_str(secret)
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id,
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver=driver,
        host=host,
        port=53,
        is_primary=True,
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    return group, server


@pytest.mark.asyncio
async def test_a_technitium_secondary_is_told_which_key_its_master_requires(
    db_session: AsyncSession,
) -> None:
    primary_group, _ = await _agent_server(db_session, "bind9", "192.0.2.10", "cHJpbWFyeQ==")
    sec_group, sec_server = await _agent_server(db_session, "technitium", "192.0.2.20", "c2Vj")
    db_session.add(
        DNSZone(
            group_id=sec_group.id,
            name="s.test.",
            zone_type="secondary",
            kind="forward",
            masters=["192.0.2.10@53"],
        )
    )
    db_session.add(
        DNSZone(
            group_id=sec_group.id,
            name="third.test.",
            zone_type="secondary",
            kind="forward",
            masters=["198.51.100.7"],
        )
    )
    await db_session.commit()

    bundle = await build_config_bundle(db_session, sec_server)
    zones = {z["name"]: z for z in bundle["zones"]}
    # The master's group shares no key with this one. Its own key is ALSO the
    # unrestricted allow-update grant on every zone it serves, so it must never
    # be shipped to another group: the zone is flagged instead.
    assert "masters_tsig_key" not in zones["s.test."]
    assert zones["s.test."]["masters_tsig_unresolved"] is True
    assert "cHJpbWFyeQ==" not in json.dumps(bundle)
    assert "master_tsig_keys" not in bundle
    # A master SpatiumDDI does not manage is authorised by address: no key, no flag.
    assert "masters_tsig_key" not in zones["third.test."]
    assert "masters_tsig_unresolved" not in zones["third.test."]

    # A key the operator placed in both groups (same name, algorithm, secret)
    # is one the master grants and this group already holds: that one is named.
    for g in (primary_group, sec_group):
        db_session.add(
            DNSTSIGKey(
                group_id=g.id,
                name="xfer-shared",
                algorithm="hmac-sha256",
                secret_encrypted=encrypt_str("c2hhcmVk"),
            )
        )
    await db_session.commit()
    bundle = await build_config_bundle(db_session, sec_server)
    zones = {z["name"]: z for z in bundle["zones"]}
    assert zones["s.test."]["masters_tsig_key"] == "xfer-shared"
    assert "masters_tsig_unresolved" not in zones["s.test."]
    assert "cHJpbWFyeQ==" not in json.dumps(bundle)


@pytest.mark.asyncio
async def test_a_same_name_key_with_another_secret_is_not_used(db_session: AsyncSession) -> None:
    primary_group, _ = await _agent_server(db_session, "bind9", "192.0.2.10", "cHJpbWFyeQ==")
    sec_group, sec_server = await _agent_server(db_session, "technitium", "192.0.2.20", "c2Vj")
    for g, secret in ((primary_group, "b25l"), (sec_group, "dHdv")):
        db_session.add(DNSTSIGKey(group_id=g.id, name="xfer", secret_encrypted=encrypt_str(secret)))
    db_session.add(
        DNSZone(
            group_id=sec_group.id,
            name="s.test.",
            zone_type="secondary",
            kind="forward",
            masters=["192.0.2.10"],
        )
    )
    await db_session.commit()
    zone = (await build_config_bundle(db_session, sec_server))["zones"][0]
    assert "masters_tsig_key" not in zone
    assert zone["masters_tsig_unresolved"] is True


@pytest.mark.asyncio
async def test_a_master_in_the_same_group_signs_with_the_group_key(
    db_session: AsyncSession,
) -> None:
    group, server = await _agent_server(db_session, "technitium", "192.0.2.20", "c2Vj")
    db_session.add(
        DNSServer(
            group_id=group.id,
            name="peer",
            driver="bind9",
            host="192.0.2.21",
            port=53,
            is_primary=False,
            agent_id=uuid.uuid4(),
        )
    )
    db_session.add(
        DNSZone(
            group_id=group.id,
            name="s.test.",
            zone_type="secondary",
            kind="forward",
            masters=["192.0.2.21"],
        )
    )
    await db_session.commit()
    zone = (await build_config_bundle(db_session, server))["zones"][0]
    assert zone["masters_tsig_key"] == group.tsig_key_name


@pytest.mark.asyncio
async def test_other_drivers_bundles_are_unchanged(db_session: AsyncSession) -> None:
    await _agent_server(db_session, "bind9", "192.0.2.10", "cHJpbWFyeQ==")
    sec_group, sec_server = await _agent_server(db_session, "bind9", "192.0.2.20", "c2Vj")
    db_session.add(
        DNSZone(
            group_id=sec_group.id,
            name="s.test.",
            zone_type="secondary",
            kind="forward",
            masters=["192.0.2.10"],
        )
    )
    await db_session.commit()
    bundle = await build_config_bundle(db_session, sec_server)
    assert all(
        "masters_tsig_key" not in z and "masters_tsig_unresolved" not in z for z in bundle["zones"]
    )
