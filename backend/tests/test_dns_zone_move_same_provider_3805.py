"""#3805 — moving a zone between two groups whose agentless servers reach
the SAME provider deleted the zone at the provider.

The commit pushes ``create`` into the target group (the provider already
holds the zone, so it is adopted) and then ``delete`` into the source group.
With one provider behind a server on each side, that delete removed the only
copy while the database said the zone was live in the new group.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.core.security import create_access_token, hash_password
from app.drivers.dns.route53 import Route53DNSDriver
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone


class _FakeProvider(Route53DNSDriver):
    """Route 53 identity rules, with the provider's zone store in memory."""

    def __init__(self) -> None:
        self.zones: set[tuple[str | None, str]] = set()
        self.calls: list[tuple[str, str]] = []

    async def apply_zone_change(self, server: Any, zone: Any, op: str, **_: Any) -> bool:
        self.calls.append((server.name, op))
        key = (self.provider_identity(server), zone.name)
        if op == "create":
            if key in self.zones:
                return False
            self.zones.add(key)
            return True
        if key not in self.zones:
            return False
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


async def _group(db: AsyncSession, name: str) -> DNSServerGroup:
    g = DNSServerGroup(name=name, description="")
    db.add(g)
    await db.flush()
    return g


async def _server(
    db: AsyncSession, group: DNSServerGroup, name: str, creds: dict[str, str] | None
) -> DNSServer:
    s = DNSServer(
        group_id=group.id,
        name=name,
        driver="route53",
        host=name,
        port=53,
        roles=["authoritative"],
        status="active",
        credentials_encrypted=encrypt_dict(creds) if creds is not None else None,
    )
    db.add(s)
    await db.flush()
    return s


async def _setup(
    db: AsyncSession, src_creds: dict[str, str], dst_creds: dict[str, str]
) -> tuple[DNSZone, DNSServerGroup]:
    src = await _group(db, f"src-{uuid.uuid4().hex[:6]}")
    dst = await _group(db, f"dst-{uuid.uuid4().hex[:6]}")
    await _server(db, src, "src-ns", src_creds)
    await _server(db, dst, "dst-ns", dst_creds)
    zone = DNSZone(group_id=src.id, name="example.com.", zone_type="primary")
    db.add(zone)
    await db.flush()
    return zone, dst


async def _move(client: AsyncClient, token: str, zone: DNSZone, dst: DNSServerGroup):
    return await client.post(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/move/commit",
        json={
            "target_group_id": str(dst.id),
            "confirmation_zone_name": zone.name,
            "acknowledgements": [],
        },
        headers={"Authorization": f"Bearer {token}"},
    )


_A = {"access_key_id": "AKIA-ONE", "secret_access_key": "s"}
_B = {"access_key_id": "AKIA-TWO", "secret_access_key": "s"}


@pytest.mark.asyncio
async def test_same_provider_move_keeps_the_zone_at_the_provider(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _A)
    provider.zones.add(("route53:key:AKIA-ONE", zone.name))

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert provider.zones == {("route53:key:AKIA-ONE", zone.name)}
    assert ("src-ns", "delete") not in provider.calls
    assert ("dst-ns", "create") in provider.calls


@pytest.mark.asyncio
async def test_same_provider_preview_says_the_source_copy_is_kept(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _A)
    resp = await client.post(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/move/preview",
        json={"target_group_id": str(dst.id)},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    assert any("Source copy kept on 'src-ns'" in w for w in resp.json()["warnings"])


@pytest.mark.asyncio
async def test_different_providers_still_delete_the_source_copy(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _B)
    provider.zones.add(("route53:key:AKIA-ONE", zone.name))

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert provider.zones == {("route53:key:AKIA-TWO", zone.name)}
    assert ("src-ns", "delete") in provider.calls


@pytest.mark.asyncio
async def test_unknown_identity_does_not_delete_and_warns(
    client: AsyncClient,
    db_session: AsyncSession,
    provider: _FakeProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, {"secret_access_key": "s"}, _B)  # no key id: unknown
    provider.zones.add(("route53:key:AKIA-TWO", zone.name))

    warned: list[dict[str, Any]] = []
    from app.services.dns import zone_move

    monkeypatch.setattr(
        zone_move.logger, "warning", lambda event, **kw: warned.append({"event": event, **kw})
    )

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert ("src-ns", "delete") not in provider.calls
    assert any(
        w["event"] == "dns.zone_move.provider_identity_unknown" and w["source_server"] == "src-ns"
        for w in warned
    )
