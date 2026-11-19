"""``ipam.nat`` feature module (#2100).

NAT mappings ship default-OFF, but an install that already holds mappings
must keep seeing them after upgrade — without a seeded ``feature_module``
row, which #1069 forbids. ``ModuleSpec.default_on_if_rows_in`` does that:
with no operator override, the module resolves ON iff ``nat_mapping`` has a
row. These tests pin all three resolution cases, the route gate, the address
list's NAT count, the round trip back on, and that the firewall mirrors keep
writing while the module is off.

The suite-wide ``conftest._all_feature_modules_enabled`` patches every
default to True, so each test here restores ``ipam.nat``'s shipped default
first via ``_nat_shipped_default``.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Iterator

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.feature_module import FeatureModule
from app.models.fortinet import FortinetFirewall
from app.models.ipam import IPAddress, IPBlock, IPSpace, NATMapping, Subnet
from app.services import feature_modules as fm
from app.services.firewall_mirror import FORTINET_OWNER, MirrorNat, MirrorSummary, apply_nat

NAT = "ipam.nat"
NAT_URL = "/api/v1/ipam/nat-mappings"


@pytest.fixture
def _nat_shipped_default() -> Iterator[None]:
    """Put ``ipam.nat`` back to its shipped default-off for this test.

    Not ``monkeypatch``: the conftest explains why an autouse fixture must
    avoid it, and this runs alongside that one; a plain swap + restore keeps
    the ordering obvious.
    """
    before_modules, before_by_id = fm.MODULES, fm.MODULES_BY_ID
    patched = tuple(
        dataclasses.replace(m, default_enabled=False) if m.id == NAT else m for m in before_modules
    )
    fm.MODULES = patched
    fm.MODULES_BY_ID = {m.id: m for m in patched}
    fm.invalidate_cache()
    try:
        yield
    finally:
        fm.MODULES, fm.MODULES_BY_ID = before_modules, before_by_id
        fm.invalidate_cache()


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _mapping(name: str = "web") -> NATMapping:
    return NATMapping(name=name, kind="1to1", internal_ip="10.10.0.42", external_ip="203.0.113.42")


async def _module_entry(client: AsyncClient, h: dict[str, str]) -> dict:
    r = await client.get("/api/v1/admin/feature-modules", headers=h)
    assert r.status_code == 200, r.text
    return next(m for m in r.json() if m["id"] == NAT)


async def _enabled(db: AsyncSession) -> bool:
    fm.invalidate_cache()
    return NAT in await fm.get_enabled_modules(db)


# ── Default resolution: the three cases ──────────────────────────────


@pytest.mark.asyncio
@pytest.mark.usefixtures("_nat_shipped_default")
async def test_fresh_install_without_rows_is_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    await db_session.commit()

    assert not await _enabled(db_session)
    entry = await _module_entry(client, h)
    assert entry["enabled"] is False
    assert entry["default_enabled"] is False
    assert (await client.get(NAT_URL, headers=h)).status_code == 404


@pytest.mark.asyncio
@pytest.mark.usefixtures("_nat_shipped_default")
async def test_existing_rows_without_an_override_turn_it_on(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The upgrade case: mappings exist, nobody has touched the toggle."""
    h = await _superadmin(db_session)
    db_session.add(_mapping())
    await db_session.commit()

    assert await _enabled(db_session)
    entry = await _module_entry(client, h)
    assert entry["enabled"] is True
    # The effective default is on, so Settings → Features does not call an
    # untouched module "overridden".
    assert entry["default_enabled"] is True
    r = await client.get(NAT_URL, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1
    # No row was written to say so (#1069).
    assert (await db_session.get(FeatureModule, NAT)) is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("_nat_shipped_default")
async def test_an_operator_row_wins_in_both_directions(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    # On with no data.
    db_session.add(FeatureModule(id=NAT, enabled=True))
    await db_session.commit()
    assert await _enabled(db_session)
    assert (await client.get(NAT_URL, headers=h)).status_code == 200

    # Off with data.
    row = await db_session.get(FeatureModule, NAT)
    assert row is not None
    row.enabled = False
    db_session.add(_mapping())
    await db_session.commit()
    assert not await _enabled(db_session)
    assert (await client.get(NAT_URL, headers=h)).status_code == 404
    entry = await _module_entry(client, h)
    assert entry["enabled"] is False
    assert entry["default_enabled"] is True  # → shows as "overridden"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_nat_shipped_default")
async def test_the_data_probe_does_not_run_once_an_operator_has_chosen(
    db_session: AsyncSession,
) -> None:
    db_session.add(FeatureModule(id=NAT, enabled=False))
    await db_session.commit()

    async def _boom(*_a: object, **_k: object) -> bool:
        raise AssertionError("probe ran despite an override row")

    original = fm._table_has_rows
    fm._table_has_rows = _boom  # type: ignore[assignment]
    try:
        assert not await _enabled(db_session)
    finally:
        fm._table_has_rows = original  # type: ignore[assignment]


# ── Off → on round trip ───────────────────────────────────────────────


async def _subnet_with_ip(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.10.0.0/16", name="b")
    db.add(block)
    await db.flush()
    sub = Subnet(space_id=space.id, block_id=block.id, network="10.10.0.0/24", name="s")
    db.add(sub)
    await db.flush()
    db.add(IPAddress(subnet_id=sub.id, address="10.10.0.42", status="allocated"))
    await db.flush()
    return sub


@pytest.mark.asyncio
@pytest.mark.usefixtures("_nat_shipped_default")
async def test_disabling_hides_and_enabling_restores_with_data_untouched(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    sub = await _subnet_with_ip(db_session)
    db_session.add_all([_mapping("a"), _mapping("b")])
    await db_session.commit()

    async def nat_count() -> int:
        r = await client.get(f"/api/v1/ipam/subnets/{sub.id}/addresses", headers=h)
        assert r.status_code == 200, r.text
        return next(x for x in r.json() if x["address"] == "10.10.0.42")["nat_mapping_count"]

    assert await nat_count() == 2

    # Disabling with rows present is allowed.
    r = await client.patch(
        f"/api/v1/admin/feature-modules/{NAT}", headers=h, json={"enabled": False}
    )
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False
    assert (await client.get(NAT_URL, headers=h)).status_code == 404
    assert await nat_count() == 0
    assert (await db_session.execute(select(func.count(NATMapping.id)))).scalar_one() == 2

    r = await client.patch(
        f"/api/v1/admin/feature-modules/{NAT}", headers=h, json={"enabled": True}
    )
    assert r.status_code == 200, r.text
    r = await client.get(NAT_URL, headers=h)
    assert r.status_code == 200, r.text
    assert sorted(i["name"] for i in r.json()["items"]) == ["a", "b"]
    assert await nat_count() == 2


# ── Mirrors keep writing ─────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.usefixtures("_nat_shipped_default")
async def test_firewall_mirror_still_writes_nat_rows_while_off(db_session: AsyncSession) -> None:
    space = IPSpace(name=f"forti-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    fw = FortinetFirewall(
        name=f"fg-{uuid.uuid4().hex[:6]}",
        host="fg.example.test",
        port=443,
        verify_tls=False,
        api_token_encrypted=encrypt_str("TOK"),
        ipam_space_id=space.id,
        vdom="root",
    )
    db_session.add(fw)
    db_session.add(FeatureModule(id=NAT, enabled=False))
    await db_session.flush()
    assert not await _enabled(db_session)

    summary = MirrorSummary()
    await apply_nat(
        db_session,
        FORTINET_OWNER,
        fw.id,
        fw.name,
        [MirrorNat("vip-web", "1to1", "10.0.0.10", "203.0.113.10", "")],
        summary,
    )
    await db_session.commit()

    assert summary.nat_created == 1
    rows = (
        (
            await db_session.execute(
                select(NATMapping).where(NATMapping.fortinet_firewall_id == fw.id)
            )
        )
        .scalars()
        .all()
    )
    assert [r.name for r in rows] == ["vip-web"]
    # Still off: an operator's choice is not overridden by new data.
    assert not await _enabled(db_session)
