"""The role/grant action allow-list must cover every action in real use (#1631)."""

from __future__ import annotations

import ast
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.roles.router import _VALID_ACTIONS, PermissionEntry
from app.core.security import create_access_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.auth import Group, User

_APP = Path(__file__).resolve().parents[1] / "app"


def test_every_builtin_role_action_is_accepted() -> None:
    for name, (_desc, perms) in _BUILTIN_ROLES.items():
        for p in perms:
            # A clone of a builtin role must round-trip through the API schema.
            PermissionEntry(**p)  # type: ignore[arg-type]
            assert p["action"] in _VALID_ACTIONS, name


def test_cloned_change_approver_validates() -> None:
    entry = PermissionEntry(action="approve", resource_type="change_request")
    assert entry.action == "approve"
    with pytest.raises(ValidationError):
        PermissionEntry(action="bogus", resource_type="x")


# Permission helpers and the position of their ``action`` argument. Every
# literal action passed to one of these must be grantable through the API, or
# a role that should satisfy the check cannot be saved (#1631).
_ACTION_ARG = {
    "user_has_permission": 1,
    "has_any_grant_for": 1,
    "require_permission": 0,
}


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _actions_in_call(node: ast.Call) -> list[str | None]:
    fn = node.func
    name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
    if name in _ACTION_ARG:
        kw = next((k.value for k in node.keywords if k.arg == "action"), None)
        pos = _ACTION_ARG[name]
        arg = kw if kw is not None else (node.args[pos] if len(node.args) > pos else None)
        return [_literal(arg)]
    if name == "require_any_permission":
        # ``*pairs`` of ``(action, resource_type)`` — every pair, not the first.
        return [_literal(a.elts[0]) for a in node.args if isinstance(a, ast.Tuple) and a.elts]
    return []


def test_actions_checked_in_code_are_grantable() -> None:
    used: set[str] = set()
    calls = 0
    for path in _APP.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for action in _actions_in_call(node):
                    calls += 1
                    if action is not None:
                        used.add(action)
    # Guards that the scan is evaluating at all: hundreds of call sites exist,
    # and the approval checks (#62, #696) pass ``approve`` as a literal.
    assert calls > 100, calls
    assert {"read", "write", "approve"} <= used, used
    assert used <= _VALID_ACTIONS, used - _VALID_ACTIONS


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="SA",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


_APPROVER_PERMS = [
    {"action": "approve", "resource_type": "change_request"},
    {"action": "read", "resource_type": "change_request"},
]


async def test_approver_role_creates_and_saves_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's reproduction: a role holding Change Approver's grants is
    created, and then saved again with those grants unchanged."""
    headers = await _superadmin_headers(db_session)
    r = await client.post(
        "/api/v1/roles",
        json={"name": "approver-1631", "permissions": _APPROVER_PERMS},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    role_id = r.json()["id"]
    r = await client.post(
        f"/api/v1/roles/{role_id}/clone", json={"name": "approver-1631-clone"}, headers=headers
    )
    assert r.status_code == 201, r.text
    clone_id = r.json()["id"]
    r = await client.put(
        f"/api/v1/roles/{clone_id}",
        json={"name": "approver-1631-clone", "permissions": r.json()["permissions"]},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert {p["action"] for p in r.json()["permissions"]} == {"approve", "read"}


async def test_time_bound_approve_grant_is_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A temporary approver (#65 grants share the role vocabulary)."""
    headers = await _superadmin_headers(db_session)
    g = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(g)
    await db_session.commit()
    r = await client.post(
        "/api/v1/groups/time-bound-grants",
        json={
            "group_id": str(g.id),
            "action": "approve",
            "resource_type": "change_request",
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
            "reason": "covering the change window",
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
