"""Guard: a freshly ``db.add()``-ed object's ``.id`` is None until flush (#2006).

``UUIDPrimaryKeyMixin`` sets ``default=uuid.uuid4``, a *column* default that
SQLAlchemy applies at flush.  Reading ``obj.id`` between ``db.add(obj)`` and
the next ``flush`` / ``commit`` / ``refresh`` therefore yields ``None`` --
``str(None)`` is the literal ``"None"`` in the audit row's ``resource_id``.

Static check over ``backend/app``: inside one function, flag any read of
``X.id`` that comes after ``<db>.add(X)`` with no flush/commit/refresh/
``begin_nested`` call (and no explicit ``id=`` / ``X.id = ...``) in between.
"""

from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"
_BARRIERS = {"flush", "commit", "refresh", "execute", "scalar", "scalars"}


# (path, variable) pairs that read ``.id`` of a row that was *loaded*, not new,
# so the id is already populated -- the add() there only re-attaches it.
_ALLOWED = {("app/services/cutover/readiness.py", "item")}


def _has_explicit_id(call: ast.AST) -> bool:
    return isinstance(call, ast.Call) and any(k.arg == "id" for k in call.keywords)


def _scan(fn: ast.AST, path: Path) -> list[str]:
    assigned_with_id: set[str] = set()
    events: list[tuple[int, int, str, str]] = []  # (line, col, kind, name)
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            if _has_explicit_id(node.value):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        assigned_with_id.add(t.id)
            for t in node.targets:
                if (
                    isinstance(t, ast.Attribute)
                    and t.attr == "id"
                    and isinstance(t.value, ast.Name)
                ):
                    assigned_with_id.add(t.value.id)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "add" and len(node.args) == 1:
                if isinstance(node.args[0], ast.Name):
                    events.append((node.lineno, node.col_offset, "add", node.args[0].id))
            elif node.func.attr in _BARRIERS:
                events.append((node.lineno, node.col_offset, "barrier", ""))
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "id"
            and isinstance(node.ctx, ast.Load)
            and isinstance(node.value, ast.Name)
        ):
            events.append((node.lineno, node.col_offset, "read", node.value.id))
    events.sort()
    pending: set[str] = set()
    out: list[str] = []
    for line, _col, kind, name in events:
        if kind == "add":
            if name not in assigned_with_id:
                pending.add(name)
        elif kind == "barrier":
            pending.clear()
        elif kind == "read" and name in pending:
            rel = str(path.relative_to(APP.parent))
            if (rel, name) not in _ALLOWED:
                out.append(f"{rel}:{line}: {name}.id read before flush")
    return out


def find_violations() -> list[str]:
    found: list[str] = []
    for path in sorted(APP.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.extend(_scan(node, path))
    return sorted(set(found))


def test_no_id_read_between_add_and_flush() -> None:
    assert not find_violations(), (
        "obj.id is None until flush (column default). Add `await db.flush()` "
        "after db.add(obj) before reading obj.id:\n" + "\n".join(find_violations())
    )


# ── API-level: the audit row names the created resource ──────────────


async def _headers(db):  # type: ignore[no-untyped-def]
    import uuid

    from app.core.security import create_access_token, hash_password
    from app.models.auth import User

    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("pw"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _create_audit_resource_id(db, resource_type: str, rid: str) -> list[str]:  # type: ignore[no-untyped-def]
    from sqlalchemy import select

    from app.models.audit import AuditLog

    rows = (
        (
            await db.execute(
                select(AuditLog.resource_id).where(
                    AuditLog.resource_type == resource_type, AuditLog.action == "create"
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


import pytest  # noqa: E402


@pytest.mark.asyncio
async def test_alert_rule_create_audit_names_the_rule(client, db_session) -> None:  # type: ignore[no-untyped-def]
    h = await _headers(db_session)
    r = await client.post(
        "/api/v1/alerts/rules",
        headers=h,
        json={"name": "audit-id", "rule_type": "subnet_utilization"},
    )
    assert r.status_code == 201, r.text
    assert await _create_audit_resource_id(db_session, "alert_rule", "") == [r.json()["id"]]


@pytest.mark.asyncio
async def test_dns_group_create_audit_names_the_row(client, db_session) -> None:  # type: ignore[no-untyped-def]
    h = await _headers(db_session)
    g = await client.post("/api/v1/dns/groups", headers=h, json={"name": "audit-g"})
    assert g.status_code == 201, g.text
    assert await _create_audit_resource_id(db_session, "dns_server_group", "") == [g.json()["id"]]
