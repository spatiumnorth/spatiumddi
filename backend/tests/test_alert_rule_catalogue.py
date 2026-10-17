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


def _evaluator_reads() -> dict[str, set[str]]:
    """rule_type -> the parameter columns its dispatch branch's evaluators read."""
    tree = ast.parse(inspect.getsource(alerts))
    consts = {
        n.targets[0].id: n.value.value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id.startswith("RULE_TYPE_")
        and isinstance(n.value, ast.Constant)
    }
    reads: dict[str, set[str]] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            reads[fn.name] = {
                a.attr
                for a in ast.walk(fn)
                if isinstance(a, ast.Attribute)
                and a.attr in PARAM_COLUMNS
                and isinstance(a.value, ast.Name)
                and a.value.id == "rule"
            }
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
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in reads:
                    used |= reads[c.func.id]
        for nm in names:
            if nm in consts:
                out.setdefault(consts[nm], set()).update(used)
    return out


def test_declared_params_match_what_each_evaluator_reads() -> None:
    reads = _evaluator_reads()
    assert len(reads) > 50, "dispatch scan found too few branches — did evaluate_all move?"
    problems: list[str] = []
    for spec in build_catalogue():
        declared = {p.name for p in spec.params}
        assert declared <= set(PARAM_COLUMNS), spec.rule_type
        if spec.rule_type not in reads:
            continue  # externally driven: no dispatch branch, no params
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
    from app.models.auth import User

    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db_session.add(u)
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
