"""Regression tests for #400 / GHSA-mj4g-hw3m-62rm — M2 + M5 + L6.

M2: ``GET /api/v1/dashboards/security/summary`` returned per-user
    user/MFA/token/login telemetry (usernames, last-login times,
    failed-login source IPs, permission-change actors) to ANY
    authenticated caller — no permission gate. After the fix the
    per-row detail lists populate only for an effective superadmin or a
    caller holding ``read`` on ``audit_log`` / ``user``; everyone else
    gets the aggregate headline counts with the PII lists stripped.

M5: ``GET /api/v1/health/platform`` is mounted UNAUTHENTICATED and
    echoed raw ``str(exc)`` backend exception strings (DSNs, internal
    hosts, driver versions) in each component's ``detail`` on error.
    After the fix error details are fixed generic strings; the
    ``ok`` / ``error`` / ``warn`` status semantics are unchanged.

L6: ``GET /api/v1/version`` disclosed the appliance hostname +
    appliance version to UNAUTHENTICATED callers. After the fix those
    two fields are returned only to authenticated callers. (#2935 later
    withheld the bare ``version`` and the release check too.)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import app.api.health as health_module
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.settings import PlatformSettings

_SECURITY_URL = "/api/v1/dashboards/security/summary"


async def _ensure_settings(db: AsyncSession) -> None:
    if await db.get(PlatformSettings, 1) is None:
        db.add(PlatformSettings(id=1))
        await db.flush()


async def _user(
    db: AsyncSession,
    *,
    is_superadmin: bool = False,
    last_login: datetime | None = None,
) -> User:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        hashed_password=hash_password("OldPass123!"),
        auth_source="local",
        is_active=True,
        is_superadmin=is_superadmin,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
        last_login_at=last_login,
    )
    db.add(u)
    await db.flush()
    return u


async def _grant_role(db: AsyncSession, user: User, perms: list[dict]) -> None:
    """Attach a fresh group + role carrying ``perms`` to ``user``."""
    role = Role(name=f"r-{uuid.uuid4().hex[:8]}", permissions=perms)
    group = Group(name=f"g-{uuid.uuid4().hex[:8]}")
    group.roles.append(role)
    group.users.append(user)
    db.add_all([role, group])
    await db.flush()


def _bearer(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _seed_security_signals(db: AsyncSession) -> None:
    """Seed one PII-bearing row in each panel so the detail lists are
    non-empty for a privileged caller (and provably stripped otherwise)."""
    # An unenrolled local user (MFA panel) — its last_login_at is PII.
    await _user(db, last_login=datetime.now(UTC))
    # A failed-login burst (source_ip is PII).
    db.add(
        AuditLog(
            user_display_name="victim",
            auth_source="local",
            source_ip="203.0.113.7",
            action="login",
            resource_type="user",
            resource_id="",
            resource_display="victim",
            result="failure",
            timestamp=datetime.now(UTC),
        )
    )
    # A permission change (actor is PII).
    db.add(
        AuditLog(
            user_display_name="some-admin",
            auth_source="local",
            action="update",
            resource_type="role",
            resource_id=str(uuid.uuid4()),
            resource_display="editor",
            result="success",
            timestamp=datetime.now(UTC),
        )
    )


# ── M2: per-user PII is withheld from non-privileged callers ────────────────


async def test_security_summary_strips_pii_for_unprivileged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _ensure_settings(db_session)
    await _seed_security_signals(db_session)
    # A plain authenticated user with no groups / roles → not privileged.
    plain = await _user(db_session)
    await db_session.commit()

    r = await client.get(_SECURITY_URL, headers=_bearer(plain))
    assert r.status_code == 200, r.text
    body = r.json()
    # Aggregate counts still render (tile not blank)...
    assert body["mfa_total_local_users"] >= 1
    assert body["failed_login_total"] >= 1
    assert body["permission_change_count"] >= 1
    # ...but every PII-bearing detail list is empty.
    assert body["mfa_unenrolled"] == []
    assert body["api_tokens_expiring"] == []
    assert body["failed_login_top_sources"] == []
    assert body["permission_changes"] == []
    # ...and the summary says so, so a client can tell withheld from none (#3235).
    assert body["detail_withheld"] is True


async def test_security_summary_full_detail_for_superadmin(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _ensure_settings(db_session)
    await _seed_security_signals(db_session)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()

    r = await client.get(_SECURITY_URL, headers=_bearer(admin))
    assert r.status_code == 200, r.text
    body = r.json()
    # The superadmin sees the source IP + actor that were stripped above.
    assert any(row["source_ip"] == "203.0.113.7" for row in body["failed_login_top_sources"])
    assert any(row["actor"] == "some-admin" for row in body["permission_changes"])
    assert len(body["mfa_unenrolled"]) >= 1
    assert body["detail_withheld"] is False


async def test_security_summary_full_detail_for_audit_reader(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A non-superadmin holding read/audit_log is privileged (no 403)."""
    await _ensure_settings(db_session)
    await _seed_security_signals(db_session)
    reader = await _user(db_session)
    await _grant_role(db_session, reader, [{"action": "read", "resource_type": "audit_log"}])
    await db_session.commit()

    r = await client.get(_SECURITY_URL, headers=_bearer(reader))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["failed_login_top_sources"], "audit reader should see the detail"


async def test_security_summary_requires_auth(client: AsyncClient) -> None:
    """The endpoint still requires authentication (CurrentUser)."""
    r = await client.get(_SECURITY_URL)
    assert r.status_code == 401, r.text


# ── M5: unauthenticated platform-health never leaks str(exc) ────────────────


async def test_platform_health_sanitises_error_details(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    """Force every component check to raise with a secret-bearing message
    and confirm none of it reaches the response body — anonymous or signed
    in. Since #2935 only a signed-in caller sees component details at all."""
    secret = "postgresql://spatium:SUPERSECRET@db-internal.prod.local:5432/ddi"
    user = await _user(db_session)
    await db_session.commit()

    class _BoomSession:
        async def __aenter__(self):  # noqa: ANN001
            raise RuntimeError(secret)

        async def __aexit__(self, *a):  # noqa: ANN001
            return False

    # Postgres + the maintenance read both go through AsyncSessionLocal.
    monkeypatch.setattr(health_module, "AsyncSessionLocal", lambda: _BoomSession())

    # No Authorization header — the anonymous attack surface gets the
    # rollup only (#2935), and the DSN appears nowhere in it.
    r = await client.get("/health/platform")
    assert r.status_code == 200, r.text
    assert secret not in r.text
    assert r.json() == {"status": "degraded"}

    r = await client.get("/health/platform", headers=_bearer(user))
    assert r.status_code == 200, r.text
    body = r.json()
    # The DSN must not appear anywhere in the serialised response.
    assert secret not in r.text
    pg = next(c for c in body["components"] if c["name"] == "postgres")
    assert pg["status"] == "error"
    assert pg["detail"] == "postgres error"
    # Status semantics intact — an errored component degrades the rollup.
    assert body["status"] == "degraded"


# ── L6: appliance hostname/version gated behind auth ────────────────────────


async def test_version_hides_appliance_fields_when_anonymous(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    from app.config import settings

    await _ensure_settings(db_session)
    await db_session.commit()
    monkeypatch.setattr(settings, "appliance_mode", True)
    monkeypatch.setattr(settings, "appliance_version", "2026.06.12-1")
    monkeypatch.setattr(settings, "appliance_hostname", "ddi-prod-01")

    r = await client.get("/api/v1/version")
    assert r.status_code == 200, r.text
    body = r.json()
    # Only the coarse handshake stays public (#2935)...
    assert body["product"] == "SpatiumDDI"
    assert body["restricted"] is True
    assert body["version"] == "restricted"
    # ...not even the deployment shape...
    assert body["appliance_mode"] is False
    # ...but the host identity / patch level is withheld from anonymous callers.
    assert body["appliance_hostname"] is None
    assert body["appliance_version"] is None


async def test_version_reveals_appliance_fields_when_authenticated(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    from app.config import settings

    await _ensure_settings(db_session)
    user = await _user(db_session)
    await db_session.commit()
    monkeypatch.setattr(settings, "appliance_mode", True)
    monkeypatch.setattr(settings, "appliance_version", "2026.06.12-1")
    monkeypatch.setattr(settings, "appliance_hostname", "ddi-prod-01")

    r = await client.get("/api/v1/version", headers=_bearer(user))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["appliance_hostname"] == "ddi-prod-01"
    assert body["appliance_version"] == "2026.06.12-1"


async def test_version_invalid_token_treated_as_anonymous(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    """A garbage Bearer must not 401 the public endpoint — it falls back to
    anonymous (appliance fields withheld), keeping the login-screen flow."""
    from app.config import settings

    await _ensure_settings(db_session)
    await db_session.commit()
    monkeypatch.setattr(settings, "appliance_mode", True)
    monkeypatch.setattr(settings, "appliance_hostname", "ddi-prod-01")

    r = await client.get("/api/v1/version", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 200, r.text
    assert r.json()["appliance_hostname"] is None
    assert r.json()["restricted"] is True
