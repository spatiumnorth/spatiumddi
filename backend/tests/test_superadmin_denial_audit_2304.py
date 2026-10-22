"""A refused SuperAdmin-only route leaves a ``denied`` audit row (#2304).

``require_permission`` has always recorded its refusals; the ``SuperAdmin``
dependency and the per-router ``_require_superadmin`` helpers raised 403 and
wrote nothing, so probing backup restore, webhooks or the diagnostics surface
with a low-privilege token was invisible to the security dashboard and to a
SIEM fed by audit forwarding.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User

pytestmark = pytest.mark.asyncio


async def _plain_user(db: AsyncSession, *, superadmin: bool = False) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="Plain",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _denied(db: AsyncSession, user: User) -> list[AuditLog]:
    res = await db.execute(
        select(AuditLog).where(AuditLog.user_id == user.id, AuditLog.result == "denied")
    )
    return list(res.scalars().all())


# (method, path) — one SuperAdmin dependency route and one route per converted
# hand-rolled helper family.
ROUTES = [
    ("POST", "/api/v1/webhooks"),  # SuperAdmin dependency
    ("POST", "/api/v1/diagnostics/errors/{id}/acknowledge"),  # diagnostics helper
    ("GET", "/api/v1/backup/sections"),  # backup router inline check
    ("GET", "/api/v1/backup/targets"),  # backup targets helper
    ("POST", "/api/v1/alerts/evaluate"),  # alerts helper
    ("GET", "/api/v1/settings/audit-forward-targets"),  # settings inline check
    ("GET", "/api/v1/settings/influxdb-targets"),
]


@pytest.mark.parametrize("method,path", ROUTES)
async def test_refusal_is_one_denied_row_and_still_403(
    client: AsyncClient, db_session: AsyncSession, method: str, path: str
) -> None:
    user, headers = await _plain_user(db_session)
    path = path.replace("{id}", str(uuid.uuid4()))

    resp = await client.request(
        method, path, headers=headers, json={} if method == "POST" else None
    )
    assert resp.status_code == 403, resp.text

    rows = await _denied(db_session, user)
    assert len(rows) == 1, [r.resource_display for r in rows]
    # The refusal body names no resource and carries no audit detail.
    assert set(resp.json()) == {"detail"}


async def test_superadmin_is_not_audited_as_denied(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, auth_headers = await _plain_user(db_session, superadmin=True)
    resp = await client.get("/api/v1/settings/influxdb-targets", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    n = await db_session.scalar(
        select(func.count()).select_from(AuditLog).where(AuditLog.result == "denied")
    )
    assert n == 0


def test_require_superadmin_is_never_called_directly() -> None:
    """``require_superadmin`` is an async dependency since #2304.

    A bare ``require_superadmin(user)`` (the pre-#2304 imperative use, on the
    ``?permanent=true`` branches and in the approval engine's operations)
    returns an un-awaited coroutine and checks nothing. Imperative callers use
    ``ensure_superadmin``.
    """
    import ast
    from pathlib import Path

    app_dir = Path(__file__).resolve().parent.parent / "app"
    offenders = []
    for path in app_dir.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name == "require_superadmin":
                offenders.append(f"{path.relative_to(app_dir)}:{node.lineno}")
    assert offenders == []


def test_converted_helper_callers_keep_the_superadmin_dependency() -> None:
    """Routes whose superadmin check lived in a shared helper on origin/main.

    The #2304 conversion deleted the helper's check; these handlers must carry
    ``SuperAdmin`` themselves or they fall back to their weaker permission.
    """
    from app.api.deps import require_superadmin
    from app.main import app
    from tests.test_builtin_roles_match_routes import _dependency_calls, _iter_routes

    must = {
        ("POST", "/api/v1/appliance/pairing-codes/{code_id}/enable"),
        ("POST", "/api/v1/appliance/pairing-codes/{code_id}/disable"),
    }
    found = set()
    for r in _iter_routes(app.routes):
        for m in r.methods:
            if (m, r.path) in must and any(
                c is require_superadmin for c in _dependency_calls(r.dependant)
            ):
                found.add((m, r.path))
    assert found == must
