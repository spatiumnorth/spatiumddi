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


# ── Validation follow-ups ──────────────────────────────────────────────────


async def _delete(client: AsyncClient, token: str, zone: DNSZone) -> Any:
    return await client.delete(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}?permanent=true",
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.mark.asyncio
async def test_a_differently_spelled_name_still_counts_as_shared(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    """A Windows pull keeps the provider's case; the provider compares without it."""
    token = await _token(db_session)
    za, zb = await _two_groups(db_session, _A, _A)
    zb.name = "Example.COM"
    await db_session.flush()
    resp = await _delete(client, token, za)
    assert resp.status_code == 204, resp.text
    assert ("ns-a", "delete") not in provider.calls


@pytest.mark.asyncio
async def test_a_sharing_zone_in_the_trash_still_counts(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    """A restore does not re-create the provider copy, so a trashed zone needs it."""
    token = await _token(db_session)
    za, zb = await _two_groups(db_session, _A, _A)
    zb.deleted_at = datetime.now(UTC)
    await db_session.flush()
    resp = await _delete(client, token, za)
    assert resp.status_code == 204, resp.text
    assert ("ns-a", "delete") not in provider.calls


@pytest.mark.asyncio
async def test_a_paused_sharing_server_still_counts(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    from sqlalchemy import update as sa_update

    token = await _token(db_session)
    za, zb = await _two_groups(db_session, _A, _A)
    await db_session.execute(
        sa_update(DNSServer).where(DNSServer.group_id == zb.group_id).values(is_enabled=False)
    )
    resp = await _delete(client, token, za)
    assert resp.status_code == 204, resp.text
    assert ("ns-a", "delete") not in provider.calls


@pytest.mark.asyncio
async def test_a_sibling_views_zone_in_the_same_group_counts(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    from app.models.dns import DNSView

    token = await _token(db_session)
    za, _zb = await _two_groups(db_session, _A, _B)
    view = DNSView(group_id=za.group_id, name=f"v{uuid.uuid4().hex[:6]}")
    db_session.add(view)
    await db_session.flush()
    db_session.add(
        DNSZone(group_id=za.group_id, view_id=view.id, name="example.com.", zone_type="primary")
    )
    await db_session.flush()
    resp = await _delete(client, token, za)
    assert resp.status_code == 204, resp.text
    assert ("ns-a", "delete") not in provider.calls


@pytest.mark.asyncio
async def test_trash_api_purge_names_the_kept_copy(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    from sqlalchemy import select

    from app.models.audit import AuditLog

    token = await _token(db_session)
    za, _zb = await _two_groups(db_session, _A, _A, trashed=True)
    resp = await client.delete(
        f"/api/v1/admin/trash/dns_zone/{za.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text
    assert ("ns-a", "delete") not in provider.calls
    assert "ns-a" in resp.headers["x-provider-copies-kept"]
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_id == str(za.id), AuditLog.action == "permanent_delete"
            )
        )
    ).scalar_one()
    assert row.new_value and row.new_value["provider_copies_kept"]


@pytest.mark.asyncio
async def test_scheduled_purge_audits_the_kept_copy(
    db_session: AsyncSession, provider: _FakeProvider
) -> None:
    from datetime import timedelta

    from sqlalchemy import select

    from app.models.audit import AuditLog
    from app.tasks.trash_purge import _purge_dns_zones

    za, _zb = await _two_groups(db_session, _A, _A, trashed=True)
    za.deleted_at = datetime.now(UTC) - timedelta(days=400)
    await db_session.flush()
    purged, skipped = await _purge_dns_zones(db_session, datetime.now(UTC))
    assert (purged, skipped) == (1, 0)
    assert ("ns-a", "delete") not in provider.calls
    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == str(za.id))))
        .scalars()
        .all()
    )
    assert any((r.new_value or {}).get("provider_copies_kept") for r in rows)


@pytest.mark.asyncio
async def test_a_move_keeps_a_copy_a_third_group_uses(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    """Source and target reach different providers; a third group shares the source's."""
    token = await _token(db_session)
    za, _zc = await _two_groups(db_session, _A, _A)
    dst = DNSServerGroup(name=f"dst-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(dst)
    await db_session.flush()
    db_session.add(
        DNSServer(
            group_id=dst.id,
            name="ns-dst",
            driver="route53",
            host="ns-dst",
            port=53,
            roles=["authoritative"],
            status="active",
            credentials_encrypted=encrypt_dict(_B),
        )
    )
    await db_session.flush()
    resp = await client.post(
        f"/api/v1/dns/groups/{za.group_id}/zones/{za.id}/move/commit",
        json={
            "target_group_id": str(dst.id),
            "confirmation_zone_name": za.name,
            "acknowledgements": [],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    assert ("ns-dst", "create") in provider.calls
    assert ("ns-a", "delete") not in provider.calls


@pytest.mark.asyncio
async def test_a_late_dispatch_does_not_resend_the_removal_of_a_kept_copy(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    """#3688's retraction re-sends a delete when a dispatch outlives the zone;
    it must honour the copy the delete kept for another group."""
    from sqlalchemy import select

    from app.models.dns import DNSRecordOp
    from app.services.dns import record_ops
    from tests.conftest import _test_engine

    token = await _token(db_session)
    za, _zb = await _two_groups(db_session, _A, _A)
    server = (
        await db_session.execute(select(DNSServer).where(DNSServer.group_id == za.group_id))
    ).scalar_one()
    op = DNSRecordOp(
        server_id=server.id,
        zone_id=za.id,
        zone_name=za.name,
        op="create",
        record={"name": "www", "type": "A", "value": "192.0.2.10"},
        state="pending",
    )
    db_session.add(op)
    await db_session.flush()
    op_id = op.id
    await db_session.commit()

    async def _rec(_server: Any, _change: Any) -> None:
        return None

    provider.apply_record_change = _rec  # type: ignore[method-assign]
    mp = pytest.MonkeyPatch()
    mp.setattr(record_ops, "get_driver", lambda _name: provider)
    try:
        claimed_at = datetime.now(UTC)
        rows = await record_ops._claim(db_session, [op_id], now=claimed_at)
        await db_session.commit()
        resp = await _delete(client, token, za)
        assert resp.status_code == 204, resp.text
        await record_ops._dispatch_claimed(
            _test_engine, server, rows, batched=False, claimed_at=claimed_at
        )
    finally:
        mp.undo()
    assert ("ns-a", "delete") not in provider.calls


# ── #3888: cross-group name lock + Windows AD identity ─────────────────────


@pytest.mark.asyncio
async def test_provider_zone_name_lock_is_taken_before_the_shared_copy_check(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider, monkeypatch: Any
) -> None:
    """#3888: the name lock comes first, so a concurrent same-name delete or
    create in another group has committed before the check reads its rows."""
    import app.api.v1.dns.router as dns_router
    import app.services.lock_order as lock_order

    events: list[str] = []
    real_lock = lock_order.lock_provider_zone_name
    real_check = dns_router.shared_zone_copy_servers

    async def _lock(db: Any, name: str) -> None:
        events.append(f"lock:{name}")
        await real_lock(db, name)

    async def _check(*a: Any, **k: Any) -> Any:
        events.append("check")
        return await real_check(*a, **k)

    monkeypatch.setattr(lock_order, "lock_provider_zone_name", _lock)
    monkeypatch.setattr(dns_router, "shared_zone_copy_servers", _check)
    token = await _token(db_session)
    za, _zb = await _two_groups(db_session, _A, _A)
    resp = await client.delete(
        f"/api/v1/dns/groups/{za.group_id}/zones/{za.id}?permanent=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204, resp.text
    assert events[:2] == ["lock:example.com.", "check"]


@pytest.mark.asyncio
async def test_trash_purge_takes_the_provider_zone_name_lock(
    db_session: AsyncSession, provider: _FakeProvider, monkeypatch: Any
) -> None:
    import app.services.lock_order as lock_order
    from app.services.dns.zone_purge import purge_trashed_zone

    names: list[str] = []

    async def _lock(db: Any, name: str) -> None:
        names.append(name)

    monkeypatch.setattr(lock_order, "lock_provider_zone_name", _lock)
    za, _zb = await _two_groups(db_session, _A, _A, trashed=True)
    await purge_trashed_zone(db_session, za)
    assert names == ["example.com."]


@pytest.mark.asyncio
async def test_provider_zone_name_lock_blocks_a_second_session(db_session: AsyncSession) -> None:
    from sqlalchemy import text

    from app.services.lock_order import (
        PROVIDER_ZONE_NAME_NS,
        _provider_zone_name_key,
        lock_provider_zone_name,
    )

    await lock_provider_zone_name(db_session, "Example.COM.")
    # Same name without case / trailing dot hashes to the same key.
    assert _provider_zone_name_key("example.com") == _provider_zone_name_key("Example.COM.")
    # Re-entrant in the holder; a distinct key is still free.
    held = (
        await db_session.execute(
            text("SELECT pg_try_advisory_xact_lock(:ns, :k)"),
            {"ns": PROVIDER_ZONE_NAME_NS, "k": _provider_zone_name_key("example.com")},
        )
    ).scalar_one()
    assert held is True
    other = (
        await db_session.execute(
            text(
                "SELECT count(*) FROM pg_locks WHERE locktype='advisory' "
                "AND classid=:ns AND granted"
            ),
            {"ns": PROVIDER_ZONE_NAME_NS},
        )
    ).scalar_one()
    assert other >= 1


def _win(host: str, username: str, port: int | None = None) -> Any:
    from types import SimpleNamespace

    creds: dict[str, Any] = {"username": username, "password": "x"}
    if port:
        creds["winrm_port"] = port
    return SimpleNamespace(host=host, credentials_encrypted=encrypt_dict(creds))


def test_windows_identity_is_the_ad_domain_not_the_host() -> None:
    """#3888: two DCs of one domain share AD-integrated zones."""
    from app.drivers.dns.windows import WindowsDNSDriver

    d = WindowsDNSDriver()
    a = d.provider_identity(_win("dc1.corp.example.com", "svc@corp.example.com"))
    b = d.provider_identity(_win("dc2.corp.example.com", "CORP\\svc", port=5986))
    c = d.provider_identity(_win("10.0.0.5", "svc@Corp.Example.com"))
    assert a == b == c == "windows_dns:ad:corp.example.com"
    assert d.provider_identity(_win("dc1.other.test", "svc")) != a
    # An alternate UPN suffix must not split two DCs of one domain.
    assert d.provider_identity(_win("dc3.corp.example.com", "svc@contoso.com")) == a
    # IP + NetBIOS login: unknown, which callers treat as shared.
    assert d.provider_identity(_win("10.0.0.5", "CORP\\svc")) is None
