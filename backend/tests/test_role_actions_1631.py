"""The role/grant action allow-list must cover every action in real use (#1631)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.api.v1.roles.router import _VALID_ACTIONS, PermissionEntry
from app.main import _BUILTIN_ROLES

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


def test_actions_checked_in_code_are_grantable() -> None:
    """Every literal action passed to user_has_permission / require_*permission."""
    used: set[str] = set()
    for path in _APP.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            if name == "user_has_permission" and len(node.args) >= 2:
                arg = node.args[1]
            elif name in ("require_permission", "require_any_permission") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Tuple) and arg.elts:
                    arg = arg.elts[0]
            else:
                continue
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                used.add(arg.value)
    assert used, "scan found nothing; the pin is not evaluating"
    assert "approve" in used
    assert used <= _VALID_ACTIONS, used - _VALID_ACTIONS
