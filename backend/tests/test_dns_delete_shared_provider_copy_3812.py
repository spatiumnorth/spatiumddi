"""#3812 — deleting a zone (permanent, or purged from Trash) removed the only
provider copy of a same-named zone another group still uses."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.core.security import create_access_token, hash_password
from app.drivers.dns.route53 import Route53DNSDriver
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone

_A = {"access_key_id": "AKIA-ONE", "secret_access_key": "s"}
_B = {"access_key_id": "AKIA-TWO", "secret_access_key": "s"}


class _FakeProvider(Route53DNSDriver):
    def __init__(self) -> None:
        self.zones: set[tuple[str | None, str]] = set()
        self.calls: list[tuple[str, str]] = []

    async def apply_zone_change(self, server: Any, zone: Any, op: str, **_: Any) -> bool:
        self.calls.append((server.name, op))
        key = (self.provider_identity(server), zone.name)
        if op == "create":
            self.zones.add(key)
            return True
        self.zones.discard(key)
        return True


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> _FakeProvider:
    fake = _FakeProvider()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    return fake


async def _token(db: AsyncSession) -> str:
    u = User(
        username=f"root{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="root",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return create_access_token(str(u.id))


async def _two_groups(
    db: AsyncSession, creds_a: dict[str, str], creds_b: dict[str, str], trashed: bool = False
) -> tuple[DNSZone, DNSZone]:
    zones = []
    for tag, creds in (("a", creds_a), ("b", creds_b)):
        g = DNSServerGroup(name=f"g{tag}-{uuid.uuid4().hex[:6]}", description="")
        db.add(g)
        await db.flush()
        db.add(
            DNSServer(
                group_id=g.id,
                name=f"ns-{tag}",
                driver="route53",
                host=f"ns-{tag}",
                port=53,
                roles=["authoritative"],
                status="active",
                credentials_encrypted=encrypt_dict(creds),
            )
        )
        z = DNSZone(group_id=g.id, name="example.com.", zone_type="primary")
        db.add(z)
        await db.flush()
        zones.append(z)
    if trashed:
        zones[0].deleted_at = datetime.now(UTC)
        await db.flush()
    return zones[0], zones[1]


@pytest.mark.asyncio
async def test_permanent_delete_keeps_a_copy_the_other_group_uses(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    token = await _token(db_session)
    za, _zb = await _two_groups(db_session, _A, _A)
    provider.zones.add(("route53:key:AKIA-ONE", "example.com."))
    resp = await client.delete(
        f"/api/v1/dns/groups/{za.group_id}/zones/{za.id}?permanent=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text
    assert ("ns-a", "delete") not in provider.calls
    assert provider.zones == {("route53:key:AKIA-ONE", "example.com.")}
    assert "ns-a" in resp.headers["x-provider-copies-kept"]


@pytest.mark.asyncio
async def test_permanent_delete_still_deletes_at_a_different_provider(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    token = await _token(db_session)
    za, _zb = await _two_groups(db_session, _A, _B)
    provider.zones.add(("route53:key:AKIA-ONE", "example.com."))
    resp = await client.delete(
        f"/api/v1/dns/groups/{za.group_id}/zones/{za.id}?permanent=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text
    assert ("ns-a", "delete") in provider.calls
    assert provider.zones == set()


@pytest.mark.asyncio
async def test_trash_purge_keeps_a_copy_the_other_group_uses(
    db_session: AsyncSession, provider: _FakeProvider
) -> None:
    from app.services.dns.zone_purge import purge_trashed_zone

    za, _zb = await _two_groups(db_session, _A, _A, trashed=True)
    provider.zones.add(("route53:key:AKIA-ONE", "example.com."))
    kept = await purge_trashed_zone(db_session, za)
    assert ("ns-a", "delete") not in provider.calls
    assert provider.zones == {("route53:key:AKIA-ONE", "example.com.")}
    assert len(kept) == 1 and "ns-a" in kept[0]


@pytest.mark.asyncio
async def test_trash_purge_unknown_identity_counts_as_shared(
    db_session: AsyncSession, provider: _FakeProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.dns.zone_purge import purge_trashed_zone

    za, _zb = await _two_groups(db_session, _A, _B, trashed=True)
    monkeypatch.setattr(provider, "provider_identity", lambda server: None)
    kept = await purge_trashed_zone(db_session, za)
    assert ("ns-a", "delete") not in provider.calls
    assert kept
