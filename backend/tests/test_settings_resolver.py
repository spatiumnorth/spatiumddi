"""Settings-router tests for the DNS resolver config (issue #158).

Covers both the combined ``/settings`` PUT (resolver_* fields) and the
dedicated ``GET/PUT /settings/resolver`` endpoints:

* GET /settings/resolver returns defaults.
* PUT (superadmin) persists + audits (resource_id='resolver') + wakes
  HOSTCONFIG_ALL.
* PUT non-privileged → 403.
* invalid mode / dnssec / dot / resolver IP → 422.
* demo-mode forbidden.
* revert to automatic.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import PlatformSettings


async def _make_user(db: AsyncSession, *, username: str, superadmin: bool) -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    token = create_access_token(str(user.id))
    return user, token


@pytest.mark.asyncio
async def test_get_resolver_defaults(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_user(db_session, username="ressuper0", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.get("/api/v1/settings/resolver", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resolver_mode"] == "automatic"
    assert body["resolver_servers"] == []
    assert body["resolver_dnssec"] == "allow-downgrade"
    assert body["resolver_dns_over_tls"] == "no"


@pytest.mark.asyncio
async def test_put_resolver_persists_audits_wakes(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, token = await _make_user(db_session, username="ressuper1", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    woke: list[str] = []

    async def _capture(channel: str) -> int:
        woke.append(channel)
        return 0

    monkeypatch.setattr("app.api.v1.settings.router.publish_wake", _capture)

    resp = await client.put(
        "/api/v1/settings/resolver",
        headers=headers,
        json={
            "resolver_mode": "override",
            "resolver_servers": ["1.1.1.1", "9.9.9.9"],
            "resolver_fallback_servers": ["8.8.8.8"],
            "resolver_search_domains": ["corp.example.com"],
            "resolver_dnssec": "yes",
            "resolver_dns_over_tls": "opportunistic",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resolver_mode"] == "override"
    assert body["resolver_servers"] == ["1.1.1.1", "9.9.9.9"]
    assert body["resolver_search_domains"] == ["corp.example.com"]

    # Persisted.
    settings = await db_session.get(PlatformSettings, 1)
    assert settings is not None
    assert settings.resolver_mode == "override"
    assert settings.resolver_dnssec == "yes"

    # Woke HOSTCONFIG_ALL.
    from app.core.agent_wake import HOSTCONFIG_ALL

    assert HOSTCONFIG_ALL in woke

    # Dedicated audit row.
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "platform_settings",
                    AuditLog.resource_id == "resolver",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].action == "update"
    assert rows[0].new_value["mode"] == "override"
    assert rows[0].new_value["servers"] == ["1.1.1.1", "9.9.9.9"]
    assert "servers" in rows[0].changed_fields


@pytest.mark.asyncio
async def test_combined_put_resolver_also_audits(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # resolver_* on the shared /settings PUT also writes the dedicated row.
    _, token = await _make_user(db_session, username="ressuper2", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"resolver_mode": "override", "resolver_servers": ["1.0.0.1"]},
    )
    assert resp.status_code == 200, resp.text
    # Combined read carries resolver_* too.
    assert resp.json()["resolver_servers"] == ["1.0.0.1"]
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "platform_settings",
                    AuditLog.resource_id == "resolver",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_put_resolver_denied_without_write(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="resviewer", superadmin=False)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings/resolver",
        headers=headers,
        json={"resolver_mode": "override", "resolver_servers": ["1.1.1.1"]},
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "patch",
    [
        {"resolver_mode": "bogus"},
        {"resolver_dnssec": "maybe"},
        {"resolver_dns_over_tls": "always"},
        {"resolver_servers": ["not-an-ip"]},
        {"resolver_fallback_servers": ["999.999.999.999"]},
        {"resolver_search_domains": ["has space"]},
    ],
)
async def test_put_resolver_invalid_values_422(
    db_session: AsyncSession, client: AsyncClient, patch: dict
) -> None:
    _, token = await _make_user(
        db_session, username=f"resbad{abs(hash(str(patch))) % 10000}", superadmin=True
    )
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put("/api/v1/settings/resolver", headers=headers, json=patch)
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_put_resolver_demo_mode_forbidden(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, token = await _make_user(db_session, username="resdemosuper", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    monkeypatch.setattr("app.core.demo_mode.is_demo_mode", lambda: True)
    resp = await client.put(
        "/api/v1/settings/resolver",
        headers=headers,
        json={"resolver_mode": "override", "resolver_servers": ["1.1.1.1"]},
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_put_resolver_override_empty_servers_422(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # Override mode with an empty server list routes all host DNS to an absent
    # global server set — reject it on the dedicated /settings/resolver path.
    _, token = await _make_user(db_session, username="resemptyded", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings/resolver",
        headers=headers,
        json={"resolver_mode": "override", "resolver_servers": []},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_put_resolver_override_no_servers_field_422(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # Override mode while the stored server list is empty (servers field
    # omitted entirely) must also 422 — the merged-state guard catches the
    # case the model_validator can't see.
    _, token = await _make_user(db_session, username="resnofielded", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings/resolver",
        headers=headers,
        json={"resolver_mode": "override"},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_combined_put_resolver_override_empty_servers_422(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # Same guard on the combined /settings PUT.
    _, token = await _make_user(db_session, username="resemptycomb", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"resolver_mode": "override", "resolver_servers": []},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_combined_put_resolver_override_no_servers_field_422(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # Override on the combined PUT while the stored list is empty (servers
    # field omitted) → 422 via the merged-state guard.
    _, token = await _make_user(db_session, username="resnofieldcomb", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"resolver_mode": "override"},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_put_resolver_override_with_server_succeeds(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # Override + at least one server is the valid combination — both paths.
    _, token = await _make_user(db_session, username="resokserver", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    r1 = await client.put(
        "/api/v1/settings/resolver",
        headers=headers,
        json={"resolver_mode": "override", "resolver_servers": ["1.1.1.1"]},
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["resolver_servers"] == ["1.1.1.1"]
    r2 = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"resolver_mode": "override", "resolver_servers": ["9.9.9.9"]},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["resolver_servers"] == ["9.9.9.9"]


@pytest.mark.asyncio
async def test_put_resolver_automatic_empty_servers_ok(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # The guard only applies to override — automatic + empty servers is fine
    # (the host runner tears the drop-in down and falls back to per-link DNS).
    _, token = await _make_user(db_session, username="resautoempty", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    r1 = await client.put(
        "/api/v1/settings/resolver",
        headers=headers,
        json={"resolver_mode": "automatic", "resolver_servers": []},
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["resolver_mode"] == "automatic"
    r2 = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"resolver_mode": "automatic", "resolver_servers": []},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["resolver_mode"] == "automatic"


@pytest.mark.asyncio
async def test_put_resolver_revert_to_automatic(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="resrevert", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    # Set override first.
    r1 = await client.put(
        "/api/v1/settings/resolver",
        headers=headers,
        json={"resolver_mode": "override", "resolver_servers": ["1.1.1.1"]},
    )
    assert r1.status_code == 200, r1.text
    # Revert to automatic.
    r2 = await client.put(
        "/api/v1/settings/resolver",
        headers=headers,
        json={"resolver_mode": "automatic"},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["resolver_mode"] == "automatic"
    settings = await db_session.get(PlatformSettings, 1)
    assert settings is not None
    assert settings.resolver_mode == "automatic"
