"""The rule-type catalogue cannot drift from the evaluators (#1997).

The editor's hand-kept list knew 23 of ~64 rule types. The catalogue is the
backend's single answer; these tests make it exhaustive and make its declared
parameters match what each evaluator actually reads.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from app.services import alerts
from app.services.alert_rule_catalogue import (
    PARAM_COLUMNS,
    build_catalogue,
    rule_type_names,
)


def test_catalogue_covers_every_rule_type_and_nothing_else() -> None:
    names = [s.rule_type for s in build_catalogue()]
    assert len(names) == len(set(names)), "a rule type is listed twice"
    assert sorted(alerts.RULE_TYPES - set(names)) == []
    assert sorted(set(names) - alerts.RULE_TYPES) == []
    assert rule_type_names() == set(alerts.RULE_TYPES)


# Rule types no ``evaluate_all`` branch dispatches: a task or another
# subsystem opens their events directly. Listed rather than inferred, so a
# dispatch the scan stops recognising fails loudly instead of being skipped.
_EXTERNALLY_DRIVEN = {
    alerts.RULE_TYPE_AUDIT_CHAIN_BROKEN,
    alerts.RULE_TYPE_SCHEMA_BEHIND_HEAD,
    alerts.RULE_TYPE_ACME_MANUAL_RENEWAL,
}


def _rule_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """The names an AlertRule goes by in ``fn``: ``rule``, plus any argument
    annotated ``AlertRule``."""
    names = {"rule"}
    for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]:
        if arg.annotation is not None and "AlertRule" in ast.unparse(arg.annotation):
            names.add(arg.arg)
    return names


def _direct_reads(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names = _rule_names(fn)
    out: set[str] = set()
    for n in ast.walk(fn):
        # rule.<column>
        if (
            isinstance(n, ast.Attribute)
            and n.attr in PARAM_COLUMNS
            and isinstance(n.value, ast.Name)
            and n.value.id in names
        ):
            out.add(n.attr)
        # getattr(rule, "<column>"[, default])
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "getattr"
            and len(n.args) >= 2
            and isinstance(n.args[0], ast.Name)
            and n.args[0].id in names
            and isinstance(n.args[1], ast.Constant)
            and n.args[1].value in PARAM_COLUMNS
        ):
            out.add(n.args[1].value)
    return out


def _evaluator_reads() -> dict[str, set[str]]:
    """rule_type -> the parameter columns its dispatch branch reads, following
    calls into helpers in the same module (so a read moved into a helper is
    still seen)."""
    tree = ast.parse(inspect.getsource(alerts))
    consts = {
        n.targets[0].id: n.value.value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id.startswith("RULE_TYPE_")
        and isinstance(n.value, ast.Constant)
    }
    direct: dict[str, set[str]] = {}
    callees: dict[str, set[str]] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            direct.setdefault(fn.name, set()).update(_direct_reads(fn))
            callees.setdefault(fn.name, set()).update(
                c.func.id
                for c in ast.walk(fn)
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
            )

    def closure(name: str, seen: set[str]) -> set[str]:
        if name in seen or name not in direct:
            return set()
        seen.add(name)
        out = set(direct[name])
        for c in callees[name]:
            out |= closure(c, seen)
        return out

    evaluate_all = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "evaluate_all"
    )
    out: dict[str, set[str]] = {}
    for node in ast.walk(evaluate_all):
        if not isinstance(node, ast.If):
            continue
        names = [
            x.id
            for x in ast.walk(node.test)
            if isinstance(x, ast.Name) and x.id.startswith("RULE_TYPE_")
        ]
        if not names:
            continue
        used: set[str] = set()
        for stmt in node.body:
            for c in ast.walk(stmt):
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name):
                    used |= closure(c.func.id, set())
        for nm in names:
            if nm in consts:
                out.setdefault(consts[nm], set()).update(used)
    return out


def test_every_rule_type_is_dispatched_or_declared_external() -> None:
    reads = _evaluator_reads()
    assert set(alerts.RULE_TYPES) - set(reads) == _EXTERNALLY_DRIVEN


def test_externally_driven_types_declare_no_params() -> None:
    by_type = {s.rule_type: s for s in build_catalogue()}
    for rt in _EXTERNALLY_DRIVEN:
        assert by_type[rt].params == [], rt


def test_declared_params_match_what_each_evaluator_reads() -> None:
    reads = _evaluator_reads()
    assert len(reads) > 50, "dispatch scan found too few branches — did evaluate_all move?"
    problems: list[str] = []
    for spec in build_catalogue():
        declared = {p.name for p in spec.params}
        assert declared <= set(PARAM_COLUMNS), spec.rule_type
        if spec.rule_type in _EXTERNALLY_DRIVEN:
            continue  # no dispatch branch; covered by the test above
        if declared != reads[spec.rule_type]:
            problems.append(
                f"{spec.rule_type}: declared {sorted(declared)}, "
                f"evaluator reads {sorted(reads[spec.rule_type])}"
            )
    assert problems == []


def test_select_params_carry_options_and_integers_do_not() -> None:
    for spec in build_catalogue():
        for p in spec.params:
            assert p.kind in ("integer", "select"), (spec.rule_type, p.name)
            assert bool(p.options) == (p.kind == "select"), (spec.rule_type, p.name)


def test_unadjustable_type_has_no_params() -> None:
    by_type = {s.rule_type: s for s in build_catalogue()}
    assert by_type["ip_free_but_responding"].params[0].name == "threshold_days"
    assert by_type["domain_nameserver_drift"].params == []


@pytest.mark.asyncio
async def test_endpoint_serves_the_catalogue_to_any_signed_in_user(client, db_session) -> None:
    import uuid

    from app.core.security import create_access_token, hash_password
    from app.models.auth import Group, Role, User

    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db_session.add(u)
    await db_session.flush()
    # The alert routes are gated on ``read:alert`` now.
    role = Role(
        name=f"r-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[{"action": "read", "resource_type": "alert"}],
    )
    db_session.add(role)
    await db_session.flush()
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    group.users = [u]
    db_session.add(group)
    await db_session.commit()
    tok = create_access_token(str(u.id))

    assert (await client.get("/api/v1/alerts/rule-types")).status_code in (401, 403)
    resp = await client.get("/api/v1/alerts/rule-types", headers={"Authorization": f"Bearer {tok}"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert {r["rule_type"] for r in body} == set(alerts.RULE_TYPES)
    row = next(r for r in body if r["rule_type"] == "ip_free_but_responding")
    assert row["params"][0]["name"] == "threshold_days"
    assert row["params"][0]["default"] == 1
