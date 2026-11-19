"""New Role offers every resource type the server checks (#3119).

The role editor and the time-bound grant dialog build a grant from
``GRANT_RESOURCE_TYPES`` in ``frontend/src/lib/permissionVocabulary.ts``.
A type the routes check but the list leaves out can only be reached through
``*``, which only a superadmin may grant — so a role built in the console
cannot open that surface at all. #2439 and #2621 fixed that one type at a
time; #3119 found twelve more (every integration router and the firewall
feeds), all added since.

The types are read from the running app, not from the source: the permission
factories record what they enforce in ``spatium_requires``, the copilot tools
and operations declare theirs, and the search providers name theirs. A
source scan misses a type held in a module constant (``PERMISSION = ...``),
a ``require_any_permission`` tuple, or a generated pair list — six of the
route types alone are spelled that way. Checks made inline in a handler are
invisible here; those are listed in ``CHECKED_INLINE`` beside the route walker.

Skipped rather than failed when the frontend tree is absent: the api image
ships only ``backend/``. CI checks out the whole repo, and
``ci-backend-must-run.txt`` runs this on an edit to the vocabulary file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services.ai.operations import all_operations
from app.services.ai.tools import REGISTRY
from app.services.search.providers import PROVIDERS
from tests.test_builtin_roles_match_routes import CHECKED_INLINE, route_inventory

_VOCABULARY = (
    Path(__file__).resolve().parents[2] / "frontend" / "src" / "lib" / "permissionVocabulary.ts"
)


# Operation permissions that name a type no grant can usefully carry, because
# the surface behind them is superadmin-only regardless: the operation's pair is
# a backstop checked against the approver, and a superadmin passes it via
# ``*``. Listed so a NEW operation type still has to be offered or named here.
SUPERADMIN_ONLY_OPERATION_TYPES: dict[str, str] = {
    "approval_control": "operations_control — weakening the approvals gate",
    "dhcp_server_group": "operations_risky delete_group — the REST route is SuperAdmin",
}


def _offered() -> set[str]:
    if not _VOCABULARY.is_file():
        pytest.skip("frontend/ is outside the api image; run from a checkout")
    text = _VOCABULARY.read_text()
    match = re.search(r"GRANT_RESOURCE_TYPES\s*=\s*\[(.*?)\]\s*as const", text, re.S)
    assert match, f"GRANT_RESOURCE_TYPES not found in {_VOCABULARY}"
    offered = set(re.findall(r'"([^"]+)"', match.group(1)))
    # A parse that found nothing would pass every check below vacuously.
    assert len(offered) > 40, f"parsed only {len(offered)} types from {_VOCABULARY}"
    return offered


def _route_types() -> set[str]:
    return {t for _m, _p, _sup, pairs in route_inventory() for _a, t in pairs}


def _tool_types() -> set[str]:
    types: set[str] = set()
    for tool in REGISTRY.all():
        perm = tool.permission
        if isinstance(perm, tuple):
            _action, rtypes = perm
            types.update(rtypes if isinstance(rtypes, tuple) else (rtypes,))
    return types


def _operation_types() -> set[str]:
    return {op.required_permission[1] for op in all_operations() if op.required_permission}


def _search_types() -> set[str]:
    return {t for p in PROVIDERS for t in p.resource_types}


def test_offers_every_type_a_route_checks() -> None:
    offered = _offered()
    types = _route_types()
    # The walker finding nothing (a FastAPI change in how routes nest) would
    # make the check below pass on an empty set.
    assert len(types) > 40, f"route walk found only {len(types)} resource types"
    assert sorted(types - offered) == []


def test_offers_every_type_a_copilot_tool_or_operation_checks() -> None:
    offered = _offered()
    tool_types = _tool_types()
    op_types = _operation_types()
    assert len(tool_types) > 20, f"tool registry yielded only {len(tool_types)} types"
    assert len(op_types) > 10, f"operations yielded only {len(op_types)} types"
    assert sorted(tool_types - offered) == []
    assert sorted(op_types - offered - set(SUPERADMIN_ONLY_OPERATION_TYPES)) == []


def test_offers_every_type_search_or_a_handler_checks() -> None:
    offered = _offered()
    assert sorted((_search_types() | set(CHECKED_INLINE)) - offered) == []
