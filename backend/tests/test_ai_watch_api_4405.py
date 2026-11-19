"""Copilot Watch over REST and MCP: who may do what (#4405).

Settings are superadmin-only. Findings are read with ``read`` on
``ai_finding`` and triaged with ``write`` on it. The whole surface 404s
while the ``ai.watch`` module, or its parent ``ai.copilot``, is off.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_token
from app.main import _BUILTIN_ROLES
from app.models.ai_watch import AIFinding, AIFindingMute, AIWatchRun
from app.models.auth import APIToken, User
from app.models.feature_module import FeatureModule
from app.services import feature_modules
from app.services.ai.tools import (
    REGISTRY,
    ToolPermissionDenied,
    effective_tool_names,
)
from app.services.ai.watch import runner
from tests._ai_watch_helpers import (
    NOW,
    audit_rows,
    make_provider,
    make_user,
    viewer_role,
)

BASE = "/api/v1/ai/watch"
ANALYST = _BUILTIN_ROLES["Findings Analyst"][1]
VIEWER = _BUILTIN_ROLES["Viewer"][1]
WATCH_TOOLS = ("find_ai_findings", "count_ai_findings", "get_ai_finding", "find_ai_watch_runs")


async def _finding(db: AsyncSession, **kw: Any) -> AIFinding:
    row = AIFinding(
        fingerprint=kw.pop("fingerprint", uuid.uuid4().hex),
        kind=kw.pop("kind", "outage"),
        severity=kw.pop("severity", "critical"),
        title=kw.pop("title", "ns1 is down"),
        explanation="The health check cannot reach it.",
        evidence=[
            {
                "ref": f"alert:{uuid.uuid4()}",
                "type": "alert",
                "subject": "server:srv-1",
                "display": "server_unreachable: ns1",
                "severity": "critical",
                "detail": "",
                "at": NOW.isoformat(),
                "key": {},
                "cleared": False,
            }
        ],
        recommendations=["Check the agent container."],
        confidence="high",
        state=kw.pop("state", "open"),
        first_seen_at=NOW,
        last_seen_at=NOW,
        model=kw.pop("model", "local-model"),
        **kw,
    )
    db.add(row)
    await db.commit()
    return row


async def _token(db: AsyncSession, owner: User, scopes: list[str]) -> dict[str, str]:
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=scopes,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.commit()
    return {"Authorization": f"Bearer {raw}"}


# ── Module ────────────────────────────────────────────────────────────


def test_module_ships_off_and_hangs_off_the_copilot() -> None:
    spec = feature_modules.MODULES_BY_ID["ai.watch"]
    assert spec.requires == ("ai.copilot",)
    assert spec.group == "AI"


@pytest.mark.parametrize("off", ["ai.watch", "ai.copilot"])
async def test_surface_404s_while_the_module_or_its_parent_is_off(
    client: AsyncClient, db_session: AsyncSession, off: str
) -> None:
    db_session.add(FeatureModule(id=off, enabled=False))
    _, admin = await make_user(db_session, superadmin=True)
    finding = await _finding(db_session)

    for method, path in (
        ("GET", "/config"),
        ("PUT", "/config"),
        ("POST", "/run-now"),
        ("POST", "/pause"),
        ("GET", "/findings"),
        ("GET", "/summary"),
        ("GET", "/runs"),
        ("POST", f"/findings/{finding.id}/acknowledge"),
    ):
        r = await client.request(method, BASE + path, headers=admin, json={})
        assert r.status_code == 404, (method, path, r.status_code)

    enabled = await feature_modules.get_enabled_modules(db_session)
    assert "ai.watch" not in enabled
    # ... and the tools leave the Copilot's schema with it.
    names = effective_tool_names(
        platform_enabled=None, provider_enabled=None, enabled_modules=enabled
    )
    assert not set(WATCH_TOOLS) & names


# ── Settings: superadmin only ─────────────────────────────────────────


async def test_rbac_matrix(client: AsyncClient, db_session: AsyncSession) -> None:
    """Server answer per role, for every kind of route."""
    await viewer_role(db_session)
    _, admin = await make_user(db_session, superadmin=True)
    _, viewer = await make_user(db_session, permissions=VIEWER)
    _, analyst = await make_user(db_session, permissions=ANALYST)
    _, editor = await make_user(
        db_session,
        permissions=[
            {"action": "admin", "resource_type": "subnet"},
            {"action": "admin", "resource_type": "dns_zone"},
            {"action": "read", "resource_type": "alert"},
        ],
    )
    owner, _ = await make_user(db_session, superadmin=True)
    read_token = await _token(db_session, owner, ["read"])
    dns_token = await _token(db_session, owner, ["dns:write"])
    finding = await _finding(db_session)
    fid = finding.id

    async def status_of(headers: dict[str, str], method: str, path: str, body: Any = None) -> int:
        r = await client.request(method, BASE + path, headers=headers, json=body)
        return r.status_code

    callers = {
        "superadmin": admin,
        "viewer": viewer,
        "analyst": analyst,
        "editor": editor,
        "read_token": read_token,
        "dns_token": dns_token,
    }
    expected: dict[tuple[str, str, str], dict[str, int]] = {
        # Settings and control: superadmin only. A scoped token is refused
        # at the scope gate (403) on anything that is not a read.
        ("GET", "/config", ""): dict(
            superadmin=200, viewer=403, analyst=403, editor=403, read_token=200, dns_token=403
        ),
        ("PUT", "/config", '{"max_rounds": 3}'): dict(
            superadmin=200, viewer=403, analyst=403, editor=403, read_token=403, dns_token=403
        ),
        ("POST", "/pause", '{"paused": false}'): dict(
            superadmin=200, viewer=403, analyst=403, editor=403, read_token=403, dns_token=403
        ),
        ("POST", "/run-now", ""): dict(
            superadmin=409, viewer=403, analyst=403, editor=403, read_token=403, dns_token=403
        ),
        # Reading findings: read on ai_finding. Viewer's wildcard read covers it.
        ("GET", "/findings", ""): dict(
            superadmin=200, viewer=200, analyst=200, editor=403, read_token=200, dns_token=403
        ),
        ("GET", f"/findings/{fid}", ""): dict(
            superadmin=200, viewer=200, analyst=200, editor=403, read_token=200, dns_token=403
        ),
        ("GET", "/summary", ""): dict(
            superadmin=200, viewer=200, analyst=200, editor=403, read_token=200, dns_token=403
        ),
        ("GET", "/runs", ""): dict(
            superadmin=200, viewer=200, analyst=200, editor=403, read_token=200, dns_token=403
        ),
        ("GET", "/mutes", ""): dict(
            superadmin=200, viewer=200, analyst=200, editor=403, read_token=200, dns_token=403
        ),
        ("GET", "/feedback-stats", ""): dict(
            superadmin=200, viewer=200, analyst=200, editor=403, read_token=200, dns_token=403
        ),
        # Triage: write on ai_finding. Feedback is the one that can repeat.
        ("POST", f"/findings/{fid}/feedback", '{"verdict": "useful"}'): dict(
            superadmin=200, viewer=403, analyst=200, editor=403, read_token=403, dns_token=403
        ),
    }
    for (method, path, raw), want in expected.items():
        body = json.loads(raw) if raw else None
        got = {name: await status_of(h, method, path, body) for name, h in callers.items()}
        assert got == want, (method, path)

    # The state changes, each tried as the roles that must be refused first.
    for path, body in (
        (f"/findings/{fid}/acknowledge", {}),
        (f"/findings/{fid}/dismiss", {}),
        (f"/findings/{fid}/reopen", None),
    ):
        for name in ("viewer", "editor", "read_token", "dns_token"):
            assert await status_of(callers[name], "POST", path, body) == 403, (name, path)
    assert await status_of(analyst, "POST", f"/findings/{fid}/acknowledge", {}) == 200
    assert await status_of(analyst, "POST", f"/findings/{fid}/dismiss", {"note": "known"}) == 200
    assert await status_of(analyst, "POST", f"/findings/{fid}/reopen") == 200
    mute = AIFindingMute(fingerprint="f" * 64, title="x")
    db_session.add(mute)
    await db_session.commit()
    assert await status_of(viewer, "DELETE", f"/mutes/{mute.id}") == 403
    assert await status_of(analyst, "DELETE", f"/mutes/{mute.id}") == 204

    # A refused request is itself audited.
    denied = [a for a in await audit_rows(db_session, "ai_finding") if a.result == "denied"]
    assert denied


async def test_config_starts_off_with_a_budget_and_creates_the_identity(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await viewer_role(db_session)
    _, admin = await make_user(db_session, superadmin=True)

    r = await client.get(f"{BASE}/config", headers=admin)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is False and body["paused"] is False
    assert body["allow_hosted_provider"] is False
    assert body["daily_token_budget"] == 200_000
    assert body["daily_cost_budget_usd"] == "2.00"
    assert body["enabled_tools"] is None
    assert body["principal"]["username"] == "copilot-watch"
    assert body["principal"]["roles"] == ["Viewer"]
    assert body["principal"]["problem"] is None
    assert body["blocked_reason"] == "no_provider"
    offered = {t["name"] for t in body["tools"]}
    assert "list_alerts" in offered
    assert not any(n.startswith("propose_") for n in offered)
    assert {t["name"] for t in body["tools"] if t["default"]} <= offered


async def test_enabling_needs_a_provider_watch_may_use(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await viewer_role(db_session)
    _, admin = await make_user(db_session, superadmin=True)

    r = await client.put(f"{BASE}/config", headers=admin, json={"enabled": True})
    assert r.status_code == 409 and "needs an enabled AI provider" in r.json()["detail"]

    hosted = await make_provider(db_session, "hosted", on_prem=False)
    r = await client.put(f"{BASE}/config", headers=admin, json={"enabled": True})
    assert r.status_code == 409 and "marked on-prem" in r.json()["detail"]
    assert (await client.get(f"{BASE}/config", headers=admin)).json()["enabled"] is False

    # Either the explicit switch ...
    r = await client.put(
        f"{BASE}/config", headers=admin, json={"enabled": True, "allow_hosted_provider": True}
    )
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True and r.json()["blocked_reason"] is None
    # ... which cannot be taken away again while it is the only way to run ...
    r = await client.put(f"{BASE}/config", headers=admin, json={"allow_hosted_provider": False})
    assert r.status_code == 409
    # ... or a provider marked on-prem.
    await make_provider(db_session, "local", on_prem=True)
    r = await client.put(f"{BASE}/config", headers=admin, json={"allow_hosted_provider": False})
    assert r.status_code == 200
    by_name = {p["name"]: p for p in r.json()["providers"]}
    assert by_name["local"]["eligible"] is True and by_name["hosted"]["eligible"] is False
    # Pinning the hosted one is refused while hosted use is off.
    r = await client.put(f"{BASE}/config", headers=admin, json={"provider_id": str(hosted.id)})
    assert r.status_code == 409

    changes = await audit_rows(db_session, "ai_watch", "update")
    assert changes[0].changed_fields == ["allow_hosted_provider", "enabled"]
    assert changes[0].new_value == {"enabled": True, "allow_hosted_provider": True}


async def test_config_validation(client: AsyncClient, db_session: AsyncSession) -> None:
    await viewer_role(db_session)
    _, admin = await make_user(db_session, superadmin=True)
    proposer = next(t.name for t in REGISTRY.all() if t.name.startswith("propose_"))

    for body in (
        {"daily_token_budget": 0},
        {"daily_cost_budget_usd": "0"},
        {"daily_token_budget": None},
        {"daily_cost_budget_usd": None},
        {"enabled_tools": ["list_alerts", proposer]},
        {"enabled_tools": ["no_such_tool"]},
        {"provider_id": str(uuid.uuid4())},
        {"event_debounce_seconds": 5},
        {"max_rounds": 99},
        {"autonomy_level": 3},
    ):
        r = await client.put(f"{BASE}/config", headers=admin, json=body)
        assert r.status_code == 422, (body, r.status_code, r.text)

    r = await client.put(
        f"{BASE}/config",
        headers=admin,
        json={"enabled_tools": ["list_alerts"], "sweep_interval_hours": 0},
    )
    assert r.status_code == 200
    assert r.json()["enabled_tools"] == ["list_alerts"]
    r = await client.put(f"{BASE}/config", headers=admin, json={"enabled_tools": None})
    assert r.json()["enabled_tools"] is None


async def test_pause_resume_and_run_now(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await viewer_role(db_session)
    admin_user, admin = await make_user(db_session, superadmin=True)
    await make_provider(db_session)
    queued: list[int] = []
    monkeypatch.setattr("app.tasks.ai_watch.tick.delay", lambda: queued.append(1))

    r = await client.post(f"{BASE}/run-now", headers=admin)
    assert r.status_code == 409 and "not enabled" in r.json()["detail"]

    await client.put(f"{BASE}/config", headers=admin, json={"enabled": True})
    r = await client.post(
        f"{BASE}/pause", headers=admin, json={"paused": True, "reason": "audit week"}
    )
    assert r.json()["paused"] is True
    assert (r.json()["paused_reason"], r.json()["paused_detail"]) == ("manual", "audit week")
    r = await client.post(f"{BASE}/run-now", headers=admin)
    assert r.status_code == 409 and "audit week" in r.json()["detail"]

    r = await client.post(f"{BASE}/pause", headers=admin, json={"paused": False})
    assert r.json()["paused"] is False and r.json()["paused_reason"] is None
    r = await client.post(f"{BASE}/run-now", headers=admin)
    assert r.status_code == 202
    assert queued == [1]
    config = await runner.get_config(db_session)
    await db_session.refresh(config)
    assert config.run_requested_at is not None
    assert config.run_requested_by_user_id == admin_user.id

    assert [a.action for a in await audit_rows(db_session, "ai_watch")] == [
        "update",
        "pause",
        "resume",
        "run",
    ]


# ── Findings ──────────────────────────────────────────────────────────


async def test_findings_list_filters_and_summary(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, analyst = await make_user(db_session, permissions=ANALYST)
    crit = await _finding(db_session, title="crit")
    await _finding(db_session, title="warn", severity="warning", kind="capacity")
    await _finding(db_session, title="acked", severity="info", state="acknowledged")
    await _finding(db_session, title="gone", state="resolved")
    db_session.add(AIWatchRun(trigger="sweep", state="ok", started_at=NOW, findings_opened=3))
    await db_session.commit()

    r = await client.get(f"{BASE}/findings", headers=analyst)
    assert r.json()["total"] == 3
    assert [f["title"] for f in r.json()["items"]] == ["crit", "warn", "acked"]
    assert r.json()["items"][0]["evidence"][0]["type"] == "alert"

    r = await client.get(f"{BASE}/findings?state=all", headers=analyst)
    assert r.json()["total"] == 4
    r = await client.get(f"{BASE}/findings?state=resolved", headers=analyst)
    assert [f["title"] for f in r.json()["items"]] == ["gone"]
    r = await client.get(f"{BASE}/findings?severity=warning&kind=capacity", headers=analyst)
    assert [f["title"] for f in r.json()["items"]] == ["warn"]
    assert (await client.get(f"{BASE}/findings?state=bogus", headers=analyst)).status_code == 422

    r = await client.get(f"{BASE}/summary", headers=analyst)
    body = r.json()
    assert body["open_total"] == 2
    assert body["open_by_severity"] == {"critical": 1, "warning": 1}
    assert body["acknowledged_total"] == 1
    assert body["last_run"]["findings_opened"] == 3
    assert body["enabled"] is False

    r = await client.get(f"{BASE}/findings/{crit.id}", headers=analyst)
    assert r.json()["recommendations"] == ["Check the agent container."]
    assert (await client.get(f"{BASE}/findings/{uuid.uuid4()}", headers=analyst)).status_code == 404

    runs = (await client.get(f"{BASE}/runs", headers=analyst)).json()
    assert runs["total"] == 1 and "transcript" not in runs["items"][0]
    detail = await client.get(f"{BASE}/runs/{runs['items'][0]['id']}", headers=analyst)
    assert "transcript" in detail.json()


async def test_triage_lifecycle_is_audited(client: AsyncClient, db_session: AsyncSession) -> None:
    user, analyst = await make_user(db_session, permissions=ANALYST)
    finding = await _finding(db_session, fingerprint="a" * 64)
    url = f"{BASE}/findings/{finding.id}"

    r = await client.post(f"{url}/acknowledge", headers=analyst, json={"note": "looking"})
    assert r.status_code == 200
    assert (r.json()["state"], r.json()["state_note"]) == ("acknowledged", "looking")
    assert r.json()["state_changed_by"] == user.username
    assert (await client.post(f"{url}/acknowledge", headers=analyst, json={})).status_code == 409

    r = await client.post(f"{url}/dismiss", headers=analyst, json={"note": "known", "mute_days": 3})
    assert r.json()["state"] == "dismissed"
    mutes = (await client.get(f"{BASE}/mutes", headers=analyst)).json()
    assert [(m["fingerprint"], m["title"], m["reason"]) for m in mutes] == [
        ("a" * 64, "ns1 is down", "known")
    ]
    assert mutes[0]["until"] is not None
    assert (await client.post(f"{url}/dismiss", headers=analyst, json={})).status_code == 409

    r = await client.post(f"{url}/reopen", headers=analyst)
    assert r.json()["state"] == "open"
    assert (await client.get(f"{BASE}/mutes", headers=analyst)).json() == []

    # Dismissing without a mute, and with one that never expires.
    await client.post(f"{url}/dismiss", headers=analyst, json={"mute_days": 0})
    assert (await client.get(f"{BASE}/mutes", headers=analyst)).json() == []
    await client.post(f"{url}/reopen", headers=analyst)
    await client.post(f"{url}/dismiss", headers=analyst, json={"mute_days": None})
    assert (await client.get(f"{BASE}/mutes", headers=analyst)).json()[0]["until"] is None

    resolved = await _finding(db_session, state="resolved")
    r = await client.post(f"{BASE}/findings/{resolved.id}/reopen", headers=analyst)
    assert r.status_code == 409

    actions = [a.action for a in await audit_rows(db_session, "ai_finding")]
    assert actions == ["acknowledge", "dismiss", "reopen", "dismiss", "reopen", "dismiss"]
    rows = await audit_rows(db_session, "ai_finding", "dismiss")
    assert rows[0].user_id == user.id
    assert rows[0].old_value == {"state": "acknowledged"}
    assert rows[0].new_value["muted"] is True


async def test_feedback_is_one_verdict_per_user_and_feeds_the_rates(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    alice, a = await make_user(db_session, permissions=ANALYST)
    _, b = await make_user(db_session, permissions=ANALYST)
    outage = await _finding(db_session, kind="outage", model="llama3")
    capacity = await _finding(db_session, kind="capacity", model="llama3")

    r = await client.post(
        f"{BASE}/findings/{outage.id}/feedback", headers=a, json={"verdict": "useful"}
    )
    assert r.json()["my_verdict"] == "useful"
    # Changing your mind replaces the verdict, it does not add one.
    r = await client.post(
        f"{BASE}/findings/{outage.id}/feedback",
        headers=a,
        json={"verdict": "wrong", "note": "the server was in maintenance"},
    )
    assert r.json()["my_verdict"] == "wrong"
    assert [(f["username"], f["verdict"]) for f in r.json()["feedback"]] == [
        (alice.username, "wrong")
    ]
    await client.post(
        f"{BASE}/findings/{outage.id}/feedback", headers=b, json={"verdict": "useful"}
    )
    await client.post(
        f"{BASE}/findings/{capacity.id}/feedback", headers=b, json={"verdict": "not_useful"}
    )
    r = await client.post(
        f"{BASE}/findings/{outage.id}/feedback", headers=a, json={"verdict": "brilliant"}
    )
    assert r.status_code == 422

    # Each reader sees their own verdict in the list.
    mine = (await client.get(f"{BASE}/findings", headers=b)).json()["items"]
    assert {f["kind"]: f["my_verdict"] for f in mine} == {
        "outage": "useful",
        "capacity": "not_useful",
    }

    stats = (await client.get(f"{BASE}/feedback-stats", headers=a)).json()
    by = {(s["dimension"], s["value"]): s for s in stats}
    assert (by[("kind", "outage")]["useful"], by[("kind", "outage")]["wrong"]) == (1, 1)
    assert by[("kind", "capacity")]["not_useful"] == 1
    assert by[("model", "llama3")] == {
        "dimension": "model",
        "value": "llama3",
        "useful": 1,
        "not_useful": 1,
        "wrong": 1,
    }
    assert len(await audit_rows(db_session, "ai_finding", "feedback")) == 4


# ── The service identity is not a person's account ────────────────────


async def test_service_identity_cannot_sign_in_or_be_turned_into_a_person(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await viewer_role(db_session)
    _, admin = await make_user(db_session, superadmin=True)
    body = (await client.get(f"{BASE}/config", headers=admin)).json()
    pid = body["principal"]["id"]

    r = await client.post("/api/v1/auth/login", json={"username": "copilot-watch", "password": ""})
    assert r.status_code in (401, 422)
    r = await client.post(
        "/api/v1/auth/login", json={"username": "copilot-watch", "password": "anything"}
    )
    assert r.status_code == 401

    r = await client.put(f"/api/v1/users/{pid}", headers=admin, json={"is_superadmin": True})
    assert r.status_code == 400 and "service identity" in r.json()["detail"]
    r = await client.post(
        f"/api/v1/users/{pid}/reset-password", headers=admin, json={"new_password": "Abcdef123456!"}
    )
    assert r.status_code == 400
    r = await client.delete(f"/api/v1/users/{pid}", headers=admin)
    assert r.status_code == 400 and "service identity" in r.json()["detail"]
    # Disabling it is allowed: it is a way to stop what runs as it.
    r = await client.put(f"/api/v1/users/{pid}", headers=admin, json={"is_active": False})
    assert r.status_code == 200
    principal = await db_session.scalar(select(User).where(User.username == "copilot-watch"))
    assert principal is not None and principal.is_superadmin is False


# ── Providers: the on-prem mark ───────────────────────────────────────


async def test_on_prem_mark_is_refused_for_hosted_kinds_and_cleared_when_the_url_moves(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, admin = await make_user(db_session, superadmin=True)

    r = await client.post(
        "/api/v1/ai/providers",
        headers=admin,
        json={"name": "claude", "kind": "anthropic", "is_on_prem": True},
    )
    assert r.status_code == 422 and "hosted service" in r.json()["detail"]

    r = await client.post(
        "/api/v1/ai/providers",
        headers=admin,
        json={"name": "ollama", "kind": "openai_compat", "base_url": "http://ollama.lan:11434/v1"},
    )
    assert r.status_code == 201 and r.json()["is_on_prem"] is False
    pid = r.json()["id"]
    r = await client.put(f"/api/v1/ai/providers/{pid}", headers=admin, json={"is_on_prem": True})
    assert r.json()["is_on_prem"] is True
    # Unrelated edits keep it.
    r = await client.put(f"/api/v1/ai/providers/{pid}", headers=admin, json={"priority": 5})
    assert r.json()["is_on_prem"] is True
    # Pointing the provider somewhere else drops the statement about the old place.
    r = await client.put(
        f"/api/v1/ai/providers/{pid}",
        headers=admin,
        json={"base_url": "https://api.example.com/v1"},
    )
    assert r.status_code == 200 and r.json()["is_on_prem"] is False
    # Unless the operator restates it in the same edit.
    r = await client.put(
        f"/api/v1/ai/providers/{pid}",
        headers=admin,
        json={"base_url": "http://vllm.lan/v1", "is_on_prem": True},
    )
    assert r.json()["is_on_prem"] is True


# ── MCP tools ─────────────────────────────────────────────────────────


def test_watch_tools_are_read_only_module_tagged_and_on_by_default() -> None:
    for name in WATCH_TOOLS:
        tool = REGISTRY.get(name)
        assert tool is not None, name
        assert tool.module == "ai.watch"
        assert tool.permission == ("read", "ai_finding")
        assert tool.default_enabled and not tool.writes and not tool.outbound
    assert not [
        t.name for t in REGISTRY.all() if t.module == "ai.watch" and t.name not in WATCH_TOOLS
    ]


async def test_watch_tools_need_read_on_ai_finding(db_session: AsyncSession) -> None:
    analyst, _ = await make_user(db_session, permissions=ANALYST)
    editor, _ = await make_user(
        db_session, permissions=[{"action": "admin", "resource_type": "subnet"}]
    )
    finding = await _finding(db_session, title="pool nearly full", kind="capacity")
    await _finding(db_session, state="resolved")
    db_session.add(
        AIWatchRun(trigger="event", state="skipped", skip_reason="budget_exhausted", started_at=NOW)
    )
    await db_session.commit()

    for name in WATCH_TOOLS:
        with pytest.raises(ToolPermissionDenied):
            await REGISTRY.call(name, {"id": str(finding.id)}, db=db_session, user=editor)

    found = await REGISTRY.call("find_ai_findings", {}, db=db_session, user=analyst)
    assert [f["title"] for f in found] == ["pool nearly full"]
    found = await REGISTRY.call(
        "find_ai_findings", {"state": "all", "search": "POOL"}, db=db_session, user=analyst
    )
    assert len(found) == 1
    counts = await REGISTRY.call("count_ai_findings", {}, db=db_session, user=analyst)
    assert counts["by_state"] == {"open": 1, "resolved": 1}
    assert counts["open_by_severity"] == {"critical": 1}
    one = await REGISTRY.call(
        "get_ai_finding", {"id": str(finding.id)}, db=db_session, user=analyst
    )
    assert one["recommendations"] == ["Check the agent container."]
    assert one["evidence"][0]["cleared"] is False
    missing = await REGISTRY.call("get_ai_finding", {"id": "nope"}, db=db_session, user=analyst)
    assert "error" in missing
    runs = await REGISTRY.call("find_ai_watch_runs", {}, db=db_session, user=analyst)
    assert runs[0]["skip_reason"] == "budget_exhausted"
