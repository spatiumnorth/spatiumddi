"""Deleting a block-sync target must not strand its blocks on the device (#2291).

Delete is refused (409) while the target is armed, and while push rows remain
(an unfinished / failed lift) unless ``force`` is passed. Disarming lifts the
blocks and removes the rows, after which delete succeeds.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.block_sync import BLOCK_TARGET_KINDS, NetworkBlock, NetworkBlockPush
from app.models.feature_module import FeatureModule
from app.models.ipam import IPSpace
from app.models.meraki import MerakiOrg
from app.models.opnsense import OPNsenseRouter
from app.models.panos import PANOSFirewall
from app.models.unifi import UnifiController
from app.services import feature_modules
from app.services.block_sync import reconcile

pytestmark = pytest.mark.asyncio

MODULES = [
    "security.block_sync",
    "integrations.opnsense",
    "integrations.unifi",
    "integrations.paloalto",
    "integrations.meraki",
]
# kind -> delete URL prefix
URLS = {
    "opnsense": "/api/v1/opnsense/routers",
    "unifi": "/api/v1/unifi/controllers",
    "paloalto": "/api/v1/paloalto/firewalls",
    "meraki": "/api/v1/meraki/orgs",
}
MODELS = {
    "opnsense": OPNsenseRouter,
    "unifi": UnifiController,
    "paloalto": PANOSFirewall,
    "meraki": MerakiOrg,
}


@pytest_asyncio.fixture(autouse=True)
async def _modules(db_session: AsyncSession):
    feature_modules.invalidate_cache()
    for m in MODULES:
        await db_session.merge(FeatureModule(id=m, enabled=True))
    await db_session.flush()
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


async def _token(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _target(db: AsyncSession, kind: str, armed: bool):
    s = IPSpace(name=f"bs-{uuid.uuid4().hex[:6]}", description="")
    db.add(s)
    await db.flush()
    name = f"t-{uuid.uuid4().hex[:6]}"
    if kind == "opnsense":
        t = OPNsenseRouter(
            name=name,
            host="10.0.0.1",
            api_key="ro",
            api_secret_encrypted=encrypt_str("s"),
            ipam_space_id=s.id,
            block_sync_enabled=armed,
            block_alias_name="spatiumddi_blocked",
            block_sync_api_key="rw",
            block_sync_api_secret_encrypted=encrypt_str("rws"),
        )
    elif kind == "unifi":
        t = UnifiController(
            name=name,
            mode="local",
            host="10.0.0.2",
            ipam_space_id=s.id,
            block_sync_enabled=armed,
            block_sync_auth_kind="api_key",
            block_sync_api_key_encrypted=encrypt_str("rw"),
        )
    elif kind == "paloalto":
        t = PANOSFirewall(
            name=name,
            host="pa.example.test",
            port=443,
            verify_tls=False,
            api_key_encrypted=encrypt_str("K"),
            ipam_space_id=s.id,
            block_sync_enabled=armed,
            block_tag_name="spatium-block",
            block_sync_api_key_encrypted=encrypt_str("W"),
        )
    else:
        t = MerakiOrg(
            name=name,
            org_id="123456",
            api_key_encrypted=encrypt_str("K"),
            ipam_space_id=s.id,
            block_sync_enabled=armed,
            block_sync_api_key_encrypted=encrypt_str("W"),
        )
    db.add(t)
    await db.flush()
    return t


async def _push(db: AsyncSession, kind: str, target_id: uuid.UUID) -> NetworkBlockPush:
    b = NetworkBlock(kind="ip", value="10.9.9.9", enabled=True)
    db.add(b)
    await db.flush()
    p = NetworkBlockPush(block_id=b.id, target_kind=kind, target_id=target_id, push_status="pushed")
    db.add(p)
    await db.flush()
    return p


async def test_guard_covers_every_block_sync_kind():
    assert set(URLS) == set(BLOCK_TARGET_KINDS)
    assert set(MODELS) == set(BLOCK_TARGET_KINDS)


@pytest.mark.parametrize("kind", sorted(URLS))
async def test_delete_armed_target_refused(
    client: AsyncClient, db_session: AsyncSession, kind: str
):
    t = await _target(db_session, kind, armed=True)
    tid = t.id
    await _push(db_session, kind, tid)
    hdr = await _token(db_session)
    await db_session.commit()

    for params in ({}, {"force": "true"}):  # force never overrides "armed"
        r = await client.delete(f"{URLS[kind]}/{tid}", headers=hdr, params=params)
        assert r.status_code == 409, r.text
        assert "disarm" in r.text.lower()

    db_session.expire_all()
    assert await db_session.get(MODELS[kind], tid) is not None
    pushes = (await db_session.execute(select(NetworkBlockPush))).scalars().all()
    assert len(pushes) == 1


@pytest.mark.parametrize("kind", sorted(URLS))
async def test_delete_disarmed_with_unlifted_pushes_refused_unless_forced(
    client: AsyncClient, db_session: AsyncSession, kind: str
):
    t = await _target(db_session, kind, armed=False)
    tid = t.id
    await _push(db_session, kind, tid)
    hdr = await _token(db_session)
    await db_session.commit()

    r = await client.delete(f"{URLS[kind]}/{tid}", headers=hdr)
    assert r.status_code == 409, r.text
    assert "lifted" in r.text

    r = await client.delete(f"{URLS[kind]}/{tid}", headers=hdr, params={"force": "true"})
    assert r.status_code == 204, r.text


@pytest.mark.parametrize("kind", sorted(URLS))
async def test_delete_clean_disarmed_target_succeeds(
    client: AsyncClient, db_session: AsyncSession, kind: str
):
    t = await _target(db_session, kind, armed=False)
    tid = t.id
    hdr = await _token(db_session)
    await db_session.commit()
    r = await client.delete(f"{URLS[kind]}/{tid}", headers=hdr)
    assert r.status_code == 204, r.text


class _FakeOPN:
    def __init__(self, members: list[str]) -> None:
        self.members = list(members)
        self.deleted: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def alias_list_addresses(self, alias):
        return list(self.members)

    async def alias_delete_address(self, alias, address):
        self.deleted.append(address)
        self.members.remove(address)

    async def alias_reconfigure(self):
        return None


async def test_disarm_lifts_then_delete_succeeds(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    t = await _target(db_session, "opnsense", armed=True)
    tid = t.id
    await _push(db_session, "opnsense", tid)
    hdr = await _token(db_session)
    await db_session.commit()

    fake = _FakeOPN(["10.9.9.9"])
    monkeypatch.setattr(reconcile, "_opnsense_client", lambda r: fake)
    # Disarm enqueues the lift on Celery; capture it and run it inline.
    lifts: list[tuple[str, uuid.UUID]] = []
    import importlib  # noqa: PLC0415

    bs_router = importlib.import_module("app.api.v1.block_sync.router")
    monkeypatch.setattr(bs_router, "_enqueue_lift", lambda targets: lifts.extend(targets))

    refused = await client.delete(f"{URLS['opnsense']}/{tid}", headers=hdr)
    assert refused.status_code == 409

    r = await client.put(
        f"/api/v1/block-sync/targets/opnsense/{tid}",
        headers=hdr,
        json={"block_sync_enabled": False},
    )
    assert r.status_code == 200, r.text
    assert lifts == [("opnsense", tid)]

    db_session.expire_all()
    router = await db_session.get(OPNsenseRouter, tid)
    await reconcile.lift_all_for_target(db_session, "opnsense", router)
    await db_session.commit()
    assert fake.deleted == ["10.9.9.9"]

    r = await client.delete(f"{URLS['opnsense']}/{tid}", headers=hdr)
    assert r.status_code == 204, r.text
