"""Copilot Watch: the tick, one run, and what becomes of the model's reply (#4405).

Driven with a scripted LLM (``tests/_scripted_llm.py``), so every test
states exactly what the "model" said and asserts what Watch did with it.
A test that expects no model call scripts no replies: the fake raises if
it is asked for one.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_watch import AIFindingMute, AIWatchRun
from app.models.alerts import AlertRule
from app.models.audit import AuditLog
from app.models.auth import Group, Role
from app.models.dns import DNSServer, DNSServerGroup
from app.models.settings import PlatformSettings
from app.services.ai.tools import REGISTRY
from app.services.ai.watch import evidence as ev
from app.services.ai.watch import findings as findings_svc
from app.services.ai.watch import runner
from app.services.ai.watch.principal import (
    WATCH_GROUP_NAME,
    ensure_watch_principal,
    get_watch_principal,
    principal_problem,
)
from app.services.ai.watch.tools import (
    DEFAULT_WATCH_TOOLS,
    allowable_tools,
    tool_refusal,
    tools_for_run,
    validate_allowlist,
)
from tests._ai_watch_helpers import (
    NOW,
    arm,
    audit_rows,
    draft,
    findings,
    findings_reply,
    make_alert,
    make_provider,
    request_run,
    runs,
    viewer_role,
)
from tests._scripted_llm import APIConnectionError, call, install, say

# ── The identity ──────────────────────────────────────────────────────


async def test_principal_is_a_read_only_account_that_cannot_sign_in(
    db_session: AsyncSession,
) -> None:
    await viewer_role(db_session)
    principal = await ensure_watch_principal(db_session)
    await db_session.commit()

    assert principal.username == "copilot-watch"
    assert principal.auth_source == "service"
    assert principal.hashed_password is None
    assert principal.is_superadmin is False
    assert [g.name for g in principal.groups] == [WATCH_GROUP_NAME]
    assert [r.name for r in principal.groups[0].roles] == ["Viewer"]
    assert principal_problem(principal) is None
    created = await audit_rows(db_session, "user", "create")
    assert created[-1].resource_display == "copilot-watch"
    assert created[-1].new_value["via"] == "ai_watch"

    # Asking again returns the same account and never touches its roles.
    again = await ensure_watch_principal(db_session)
    assert again.id == principal.id


async def test_principal_keeps_the_roles_an_operator_narrowed_it_to(
    db_session: AsyncSession,
) -> None:
    await viewer_role(db_session)
    await ensure_watch_principal(db_session)
    await db_session.commit()
    group = await db_session.scalar(select(Group).where(Group.name == WATCH_GROUP_NAME))
    assert group is not None
    narrow = Role(name="dns-only", permissions=[{"action": "read", "resource_type": "dns_group"}])
    db_session.add(narrow)
    await db_session.refresh(group, ["roles"])
    group.roles = [narrow]
    await db_session.commit()

    principal = await ensure_watch_principal(db_session)

    assert [r.name for r in principal.groups[0].roles] == ["dns-only"]
    assert principal_problem(principal) is None


@pytest.mark.parametrize(
    "permission",
    [
        {"action": "write", "resource_type": "subnet"},
        {"action": "admin", "resource_type": "dns_zone"},
        {"action": "*", "resource_type": "*"},
    ],
)
async def test_principal_holding_more_than_read_is_refused(
    db_session: AsyncSession, permission: dict
) -> None:
    await viewer_role(db_session)
    await ensure_watch_principal(db_session)
    group = await db_session.scalar(select(Group).where(Group.name == WATCH_GROUP_NAME))
    assert group is not None
    extra = Role(name=f"extra-{uuid.uuid4().hex[:6]}", permissions=[permission])
    db_session.add(extra)
    await db_session.refresh(group, ["roles"])
    group.roles = [*group.roles, extra]
    await db_session.commit()

    principal = await get_watch_principal(db_session)

    assert principal is not None
    assert principal_problem(principal) == "principal_not_read_only"


# ── The tool allowlist ────────────────────────────────────────────────


def test_default_tools_exist_and_can_be_offered() -> None:
    for name in DEFAULT_WATCH_TOOLS:
        tool = REGISTRY.get(name)
        assert tool is not None, name
        assert tool_refusal(tool) is None, name
        # Otherwise the platform Tool Catalog default would strip it.
        assert tool.default_enabled, name


def test_no_offerable_tool_writes_proposes_or_sends_traffic() -> None:
    offered = allowable_tools()
    assert offered
    for tool in offered:
        assert not tool.writes, tool.name
        assert not tool.name.startswith("propose_"), tool.name
        assert not tool.outbound and tool.rate_limit is None, tool.name
        assert tool.permission not in ("superadmin", "self"), tool.name
    assert "ask_yes_no" not in {t.name for t in offered}


def test_allowlist_validation_names_what_is_wrong() -> None:
    proposer = next(t.name for t in REGISTRY.all() if t.name.startswith("propose_"))
    outbound = next(t.name for t in REGISTRY.all() if t.outbound)

    problems = validate_allowlist(["list_alerts", proposer, outbound, "no_such_tool"])

    assert len(problems) == 3
    assert any(proposer in p and "stages a change" in p for p in problems)
    assert any(outbound in p and "outward" in p for p in problems)
    assert any("no_such_tool: no such tool" in p for p in problems)


async def test_run_tools_are_the_allowlist_narrowed_by_the_identitys_roles(
    db_session: AsyncSession,
) -> None:
    config = await arm(db_session)
    principal = await get_watch_principal(db_session)
    assert principal is not None

    names = {t.name for t in await tools_for_run(db_session, config=config, principal=principal, provider=None)}
    assert names == set(DEFAULT_WATCH_TOOLS)

    # A stored allowlist cannot smuggle in a tool the floor refuses.
    proposer = next(t.name for t in REGISTRY.all() if t.name.startswith("propose_"))
    config.enabled_tools = ["list_alerts", "list_subnets", proposer]
    group = principal.groups[0]
    narrow = Role(name="alerts-only", permissions=[{"action": "read", "resource_type": "alert"}])
    db_session.add(narrow)
    group.roles = [narrow]
    await db_session.commit()
    principal = await get_watch_principal(db_session)
    assert principal is not None

    names = {t.name for t in await tools_for_run(db_session, config=config, principal=principal, provider=None)}
    assert names == {"list_alerts"}


# ── Evidence ──────────────────────────────────────────────────────────


async def test_healthy_install_has_no_detector_evidence(db_session: AsyncSession) -> None:
    await arm(db_session)
    principal = await get_watch_principal(db_session)
    assert principal is not None

    pack = await ev.build_evidence_pack(db_session, principal)

    assert pack.detector_items == []


async def test_evidence_pack_and_reference_checks(db_session: AsyncSession) -> None:
    await arm(db_session)
    principal = await get_watch_principal(db_session)
    assert principal is not None
    group = DNSServerGroup(name="g1")
    db_session.add(group)
    await db_session.flush()
    down = DNSServer(name="ns-down", group_id=group.id, driver="bind9", host="192.0.2.1", status="unreachable")
    reverted = DNSServer(
        name="ns-reverted",
        group_id=group.id,
        driver="bind9",
        host="192.0.2.2",
        config_apply_status="reverted",
        config_apply_error="named-checkconf: zone example.test: bad owner name",
    )
    healthy = DNSServer(name="ns-ok", group_id=group.id, driver="bind9", host="192.0.2.3")
    db_session.add_all([down, reverted, healthy])
    await db_session.flush()
    alert = await make_alert(db_session, subject_id=str(down.id), display="ns-down")
    resolved = await make_alert(db_session, display="old")
    resolved.resolved_at = NOW
    db_session.add(
        AuditLog(
            user_display_name="alice",
            action="update",
            resource_type="dns_server",
            resource_id=str(down.id),
            resource_display="ns-down",
            changed_fields=["host"],
        )
    )
    await db_session.commit()

    pack = await ev.build_evidence_pack(db_session, principal)

    refs = {i.ref for i in pack.items}
    assert f"alert:{alert.id}" in refs
    assert f"alert:{resolved.id}" not in refs
    assert f"server:dns_server:{down.id}" in refs
    assert f"agent:dns_server:{reverted.id}" in refs
    assert not any(str(healthy.id) in r for r in refs)
    audit = [i for i in pack.items if i.type == "audit"]
    assert len(audit) == 1 and "alice update dns_server ns-down" in audit[0].display
    sent = pack.for_model()
    assert "bad owner name" in sent["agents_that_rejected_their_config"][0]["detail"]

    good, bad = await ev.verify_refs(
        db_session,
        principal,
        [
            f"alert:{alert.id}",
            f"alert:{resolved.id}",  # exists, but no longer reports a problem
            f"alert:{uuid.uuid4()}",  # no such row
            f"server:dns_server:{healthy.id}",  # exists and is healthy
            f"agent:dns_server:{reverted.id}",
            audit[0].ref,
            "alert:not-a-uuid",
            "made-up",
        ],
    )
    assert [i.ref for i in good] == [
        f"alert:{alert.id}",
        f"agent:dns_server:{reverted.id}",
        audit[0].ref,
    ]
    assert len(bad) == 5


async def test_narrowing_the_identity_narrows_the_evidence(db_session: AsyncSession) -> None:
    await arm(db_session)
    alert = await make_alert(db_session)
    principal = await get_watch_principal(db_session)
    assert principal is not None
    narrow = Role(name="dns-only", permissions=[{"action": "read", "resource_type": "dns_group"}])
    db_session.add(narrow)
    principal.groups[0].roles = [narrow]
    await db_session.commit()
    principal = await get_watch_principal(db_session)
    assert principal is not None

    pack = await ev.build_evidence_pack(db_session, principal)
    good, bad = await ev.verify_refs(db_session, principal, [f"alert:{alert.id}"])

    assert pack.items == []
    assert "open_alerts" in pack.omitted
    assert good == [] and bad == [f"alert:{alert.id}"]


# ── Parsing the reply ─────────────────────────────────────────────────


def test_parse_output_accepts_a_fenced_or_wrapped_document() -> None:
    body = findings_reply(draft("alert:x"))
    for text in (body, f"```json\n{body}\n```", f"Here you go:\n{body}\nDone."):
        drafts, invalid = findings_svc.parse_output(text)
        assert len(drafts) == 1 and invalid == 0


def test_parse_output_counts_entries_that_do_not_match_and_coerces_the_soft_fields() -> None:
    text = findings_reply(
        draft("alert:x", kind="weird", confidence="certain"),
        draft("alert:x", severity="apocalyptic"),
        {"title": "", "severity": "info"},
    )

    drafts, invalid = findings_svc.parse_output(text)

    assert invalid == 2
    assert (drafts[0].kind, drafts[0].confidence) == ("other", "medium")


@pytest.mark.parametrize("text", ["I could not find anything.", "[]", '{"result": []}'])
def test_parse_output_refuses_a_reply_that_is_not_the_document(text: str) -> None:
    with pytest.raises(findings_svc.OutputError):
        findings_svc.parse_output(text)


# ── The tick ──────────────────────────────────────────────────────────


async def test_disabled_watch_does_nothing(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await make_alert(db_session)
    install(monkeypatch, [])

    assert (await runner.tick(db_session, now=NOW))["status"] == "disabled"
    assert await runs(db_session) == []


async def test_first_tick_after_enabling_sweeps_and_a_healthy_install_costs_nothing(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session, last_sweep_at=None, alert_cursor=None)
    llm = install(monkeypatch, [])

    result = await runner.tick(db_session, now=NOW)

    assert result["status"] == "ok" and result["trigger"] == "sweep"
    (run,) = await runs(db_session)
    assert (run.state, run.evidence_count, run.tokens_in, run.tokens_out) == ("ok", 0, 0, 0)
    assert llm.requests == []
    assert await findings(db_session) == []
    # And the next tick is idle: the sweep is not due again.
    assert (await runner.tick(db_session, now=NOW + timedelta(minutes=1)))["status"] == "idle"


async def test_run_files_a_finding_from_verified_evidence_and_drops_the_rest(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session)
    a1 = await make_alert(db_session, subject_id="srv-1", display="ns1")
    a2 = await make_alert(db_session, subject_id="srv-1", display="ns1 zone lag", severity="warning")
    await request_run(db_session)
    invented = f"alert:{uuid.uuid4()}"
    llm = install(
        monkeypatch,
        [
            say(
                findings_reply(
                    draft(f"alert:{a1.id}", f"alert:{a2.id}", invented),
                    draft(invented, "alert:nonsense", title="Something else entirely"),
                ),
                prompt_tokens=900,
                completion_tokens=150,
            )
        ],
    )

    result = await runner.tick(db_session, now=NOW)

    assert result["status"] == "ok" and result["trigger"] == "manual"
    (run,) = await runs(db_session)
    assert (run.findings_opened, run.findings_dropped) == (1, 1)
    assert (run.tokens_in, run.tokens_out, run.rounds) == (900, 150, 1)
    assert run.provider_name == "local" and run.model == "local-model"
    assert run.cost_usd is None  # not on the rate sheet: unknown, not zero
    (finding,) = await findings(db_session)
    assert finding.state == "open" and finding.severity == "critical"
    # The invented reference was removed; the two real ones were kept.
    assert [e["ref"] for e in finding.evidence] == [f"alert:{a1.id}", f"alert:{a2.id}"]
    assert finding.run_id == run.id and finding.model == "local-model"

    # The transcript shows what was sent, what came back and what was dropped.
    roles = [entry["role"] for entry in run.transcript]
    assert roles == ["evidence", "assistant", "validation"]
    assert run.transcript[-1]["content"]["not_filed"][0]["title"] == "Something else entirely"
    # The model saw the evidence as data, with the refs it had to cite.
    user_message = llm.requests[0][1].messages[1].content
    assert f"alert:{a1.id}" in user_message

    # Everything Watch did is audited under its own identity.
    principal = await get_watch_principal(db_session)
    assert principal is not None
    (filed,) = await audit_rows(db_session, "ai_finding", "create")
    assert filed.user_id == principal.id and filed.new_value["via"] == "ai_watch"
    (ran,) = await audit_rows(db_session, "ai_watch_run", "run")
    assert ran.new_value["via"] == "ai_watch" and ran.new_value["findings_dropped"] == 1


async def test_later_run_updates_the_finding_instead_of_filing_it_again(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session, max_runs_per_hour=10)
    a1 = await make_alert(db_session, subject_id="srv-1")
    install(monkeypatch, [say(findings_reply(draft(f"alert:{a1.id}")))])
    await request_run(db_session)
    await runner.tick(db_session, now=NOW)
    (first,) = await findings(db_session)

    # Same subject, different wording, and a second alert on it: still one finding.
    a2 = await make_alert(db_session, subject_id="srv-1", severity="warning")
    install(
        monkeypatch,
        [say(findings_reply(draft(f"alert:{a2.id}", f"alert:{a1.id}", title="ns1 still down")))],
    )
    await request_run(db_session)
    await runner.tick(db_session, now=NOW + timedelta(minutes=10))

    (finding,) = await findings(db_session)
    assert finding.id == first.id
    assert finding.title == "ns1 still down"
    assert finding.first_seen_at == NOW
    assert finding.last_seen_at == NOW + timedelta(minutes=10)
    assert len(finding.evidence) == 2
    assert [(r.findings_opened, r.findings_updated) for r in await runs(db_session)] == [
        (1, 0),
        (0, 1),
    ]

    # The model can also name the finding it is updating, whatever it cites now.
    other = await make_alert(db_session, subject_id="srv-2")
    install(
        monkeypatch,
        [
            say(
                findings_reply(
                    draft(f"alert:{other.id}", title="wider outage", finding_id=str(first.id))
                )
            )
        ],
    )
    await request_run(db_session)
    await runner.tick(db_session, now=NOW + timedelta(minutes=20))
    (finding,) = await findings(db_session)
    assert finding.id == first.id and finding.title == "wider outage"
    assert finding.fingerprint == first.fingerprint


async def test_finding_closes_when_its_evidence_clears_without_a_model_call(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session)
    alert = await make_alert(db_session, subject_id="srv-1")
    install(monkeypatch, [say(findings_reply(draft(f"alert:{alert.id}")))])
    await request_run(db_session)
    await runner.tick(db_session, now=NOW)

    # The alert resolves and fires again: the same problem under a new id.
    alert.resolved_at = NOW + timedelta(minutes=1)
    await db_session.commit()
    rule = await db_session.get(AlertRule, alert.rule_id)
    refired = await make_alert(db_session, subject_id="srv-1", rule=rule)
    llm = install(monkeypatch, [])
    result = await runner.tick(db_session, now=NOW + timedelta(minutes=2))
    assert result["findings_resolved"] == 0
    (finding,) = await findings(db_session)
    assert finding.state == "open"
    assert finding.evidence[0]["ref"] == f"alert:{refired.id}"

    # It resolves for good: the finding closes, audited, with no model call.
    refired.resolved_at = NOW + timedelta(minutes=3)
    await db_session.commit()
    result = await runner.tick(db_session, now=NOW + timedelta(minutes=4))

    assert result["findings_resolved"] == 1
    (finding,) = await findings(db_session)
    assert finding.state == "resolved" and finding.resolved_at == NOW + timedelta(minutes=4)
    assert finding.evidence[0]["cleared"] is True
    assert llm.requests == []
    (closed,) = await audit_rows(db_session, "ai_finding", "resolve")
    assert closed.new_value == {"state": "resolved", "reason": "evidence cleared", "via": "ai_watch"}


async def test_muted_fingerprint_is_not_filed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session)
    alert = await make_alert(db_session, subject_id="srv-1")
    principal = await get_watch_principal(db_session)
    assert principal is not None
    (item,), _ = await ev.verify_refs(db_session, principal, [f"alert:{alert.id}"])
    db_session.add(AIFindingMute(fingerprint=findings_svc.fingerprint("outage", [item])))
    await request_run(db_session)
    install(monkeypatch, [say(findings_reply(draft(f"alert:{alert.id}")))])

    await runner.tick(db_session, now=NOW)

    (run,) = await runs(db_session)
    assert (run.findings_opened, run.findings_muted) == (0, 1)
    assert await findings(db_session) == []


async def test_tool_calls_run_as_the_identity_and_are_audited(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session)
    alert = await make_alert(db_session)
    await request_run(db_session)
    proposer = next(t.name for t in REGISTRY.all() if t.name.startswith("propose_"))
    llm = install(
        monkeypatch,
        [
            call("list_alerts"),
            call(proposer),  # the model tries to stage a change
            say(findings_reply(draft(f"alert:{alert.id}"))),
        ],
    )

    await runner.tick(db_session, now=NOW)

    (run,) = await runs(db_session)
    assert run.state == "ok" and run.tool_calls == 2 and run.rounds == 3
    offered = {t.name for t in llm.requests[0][1].tools}
    assert offered == set(DEFAULT_WATCH_TOOLS)
    tool_results = [e for e in run.transcript if e["role"] == "tool"]
    assert tool_results[0]["is_error"] is False
    assert tool_results[1]["is_error"] is True
    assert "disabled by the operator" in tool_results[1]["content"]
    principal = await get_watch_principal(db_session)
    assert principal is not None
    calls = await audit_rows(db_session, "ai_watch_run", "tool_call")
    assert [(c.resource_display, c.result) for c in calls] == [
        ("list_alerts", "success"),
        (proposer, "error"),
    ]
    assert all(c.user_id == principal.id and c.new_value["via"] == "ai_watch" for c in calls)


# ── Triggers ──────────────────────────────────────────────────────────


async def test_an_outage_that_opens_many_alerts_is_one_debounced_run(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session, event_debounce_seconds=300)
    install(monkeypatch, [say(findings_reply())])

    for _ in range(5):
        await make_alert(db_session)
    assert (await runner.tick(db_session, now=NOW))["status"] == "idle"
    for _ in range(35):
        await make_alert(db_session)
    assert (await runner.tick(db_session, now=NOW + timedelta(seconds=240)))["status"] == "idle"
    assert await runs(db_session) == []

    result = await runner.tick(db_session, now=NOW + timedelta(seconds=300))

    assert result["status"] == "ok" and result["trigger"] == "event"
    (run,) = await runs(db_session)
    assert run.evidence_count == 40
    # Nothing new since: no second run.
    assert (await runner.tick(db_session, now=NOW + timedelta(seconds=700)))["status"] == "idle"


async def test_an_alert_that_gets_worse_triggers_a_run_and_a_resolution_does_not(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    alert = await make_alert(db_session, severity="warning")
    other = await make_alert(db_session, severity="warning")
    await arm(db_session, event_debounce_seconds=60, alert_cursor=None)
    install(monkeypatch, [say(findings_reply())])

    # The first look only records what is already open.
    assert (await runner.tick(db_session, now=NOW))["status"] == "idle"
    other.resolved_at = NOW
    await db_session.commit()
    assert (await runner.tick(db_session, now=NOW + timedelta(minutes=5)))["status"] == "idle"
    assert (await runner.get_config(db_session)).event_pending_since is None

    alert.severity = "critical"
    await db_session.commit()
    assert (await runner.tick(db_session, now=NOW + timedelta(minutes=6)))["status"] == "idle"
    result = await runner.tick(db_session, now=NOW + timedelta(minutes=7))

    assert result["trigger"] == "event"


async def test_event_trigger_can_be_turned_off(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session, event_trigger_enabled=False, event_debounce_seconds=60)
    install(monkeypatch, [])
    await make_alert(db_session)

    assert (await runner.tick(db_session, now=NOW))["status"] == "idle"
    assert (await runner.tick(db_session, now=NOW + timedelta(minutes=5)))["status"] == "idle"


# ── Guards: a refused run is recorded, never silent ───────────────────


async def test_only_on_prem_providers_are_used_unless_hosted_is_allowed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session, "hosted", on_prem=False, priority=1)
    config = await arm(db_session, max_runs_per_hour=10)
    alert = await make_alert(db_session)
    await request_run(db_session)
    llm = install(monkeypatch, [])

    result = await runner.tick(db_session, now=NOW)

    assert result == {"status": "skipped", "reason": "hosted_not_allowed", "run_id": result["run_id"]}
    (run,) = await runs(db_session)
    assert (run.state, run.skip_reason, run.trigger) == ("skipped", "hosted_not_allowed", "manual")
    assert "on-prem" in (run.error or "")
    assert llm.requests == []
    (skipped,) = await audit_rows(db_session, "ai_watch_run", "run")
    assert skipped.result == "denied" and skipped.new_value["skip_reason"] == "hosted_not_allowed"
    # The request was spent: the skip is not repeated every minute.
    assert (await runner.tick(db_session, now=NOW + timedelta(minutes=1)))["status"] == "idle"

    # With an on-prem provider present, it is used even though the hosted
    # one has the higher priority, and a failure never falls back to hosted.
    await make_provider(db_session, "local", on_prem=True, priority=50)
    await request_run(db_session)
    llm = install(monkeypatch, [say("", raises=APIConnectionError("down"))])
    await runner.tick(db_session, now=NOW + timedelta(minutes=2))
    assert [name for name, _ in llm.requests] == ["local"]
    assert (await runs(db_session))[-1].state == "failed"

    # The separate switch is what lets a hosted provider in.
    config.allow_hosted_provider = True
    await request_run(db_session)
    llm = install(monkeypatch, [say(findings_reply(draft(f"alert:{alert.id}")))])
    await runner.tick(db_session, now=NOW + timedelta(minutes=3))
    assert [name for name, _ in llm.requests] == ["hosted"]
    assert (await runs(db_session))[-1].provider_name == "hosted"


async def test_pinned_provider_that_is_not_on_prem_is_refused(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    hosted = await make_provider(db_session, "hosted", on_prem=False)
    await make_provider(db_session, "local", on_prem=True)
    await arm(db_session, provider_id=hosted.id)
    await make_alert(db_session)
    await request_run(db_session)
    install(monkeypatch, [])

    assert (await runner.tick(db_session, now=NOW))["reason"] == "hosted_not_allowed"


async def test_no_enabled_provider_is_a_recorded_skip(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session, enabled=False)
    await arm(db_session)
    await request_run(db_session)
    install(monkeypatch, [])

    assert (await runner.tick(db_session, now=NOW))["reason"] == "no_provider"


async def test_exhausted_budget_skips_pauses_and_lifts_at_midnight(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session, daily_token_budget=1000, max_runs_per_hour=10)
    alert = await make_alert(db_session)
    await request_run(db_session)
    install(
        monkeypatch,
        [say(findings_reply(draft(f"alert:{alert.id}")), prompt_tokens=900, completion_tokens=200)],
    )

    # The run that crosses the budget finishes, and Watch then pauses itself.
    await runner.tick(db_session, now=NOW)

    config = await runner.get_config(db_session)
    assert config.paused and config.paused_reason == "budget"
    assert "1100 of 1000 tokens" in config.paused_detail
    assert config.paused_until == NOW.replace(hour=0) + timedelta(days=1)
    (paused,) = await audit_rows(db_session, "ai_watch", "pause")
    assert paused.new_value == {"reason": "budget", "via": "ai_watch"}

    # While paused nothing runs and no model is called.
    llm = install(monkeypatch, [])
    assert (await runner.tick(db_session, now=NOW + timedelta(hours=1)))["status"] == "paused"
    assert len(await runs(db_session)) == 1 and llm.requests == []

    # An operator resumes it the same day: the budget is still spent, so the
    # next run is refused, recorded as skipped, and Watch pauses again.
    runner.resume(config)
    await request_run(db_session)
    result = await runner.tick(db_session, now=NOW + timedelta(hours=2))
    assert result["reason"] == "budget_exhausted"
    last = (await runs(db_session))[-1]
    assert (last.state, last.skip_reason) == ("skipped", "budget_exhausted")
    assert "used up" in (last.error or "")
    assert (await runner.get_config(db_session)).paused

    # After 00:00 UTC it lifts by itself.
    result = await runner.tick(db_session, now=NOW + timedelta(days=1))
    assert result["status"] == "idle"
    config = await runner.get_config(db_session)
    assert not config.paused and config.paused_reason is None
    assert [a.new_value["reason"] for a in await audit_rows(db_session, "ai_watch", "resume")] == [
        "budget reset"
    ]


async def test_cost_budget_counts_models_on_the_rate_sheet(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session, model="gpt-4o")
    await arm(db_session, daily_cost_budget_usd=Decimal("0.01"))
    alert = await make_alert(db_session)
    await request_run(db_session)
    install(
        monkeypatch,
        [
            say(
                findings_reply(draft(f"alert:{alert.id}")),
                prompt_tokens=20_000,
                completion_tokens=2_000,
            )
        ],
    )

    await runner.tick(db_session, now=NOW)

    (run,) = await runs(db_session)
    assert run.cost_usd is not None and run.cost_usd > Decimal("0.01")
    config = await runner.get_config(db_session)
    assert config.paused_reason == "budget" and "cost budget" in config.paused_detail


async def test_run_token_limit_ends_the_run_as_failed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session, max_tokens_per_run=1000)
    await make_alert(db_session)
    await request_run(db_session)
    llm = install(
        monkeypatch, [call("list_alerts", prompt_tokens=900, completion_tokens=200), say("late")]
    )

    await runner.tick(db_session, now=NOW)

    (run,) = await runs(db_session)
    assert run.state == "failed" and "token limit" in (run.error or "")
    assert len(llm.requests) == 1
    assert (run.tokens_in, run.tokens_out) == (900, 200)  # still counted against the budget


async def test_runs_per_hour_limit(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> None:
    await make_provider(db_session)
    await arm(db_session, max_runs_per_hour=1)
    await make_alert(db_session)
    install(monkeypatch, [say(findings_reply())])
    await request_run(db_session)
    assert (await runner.tick(db_session, now=NOW))["status"] == "ok"

    await request_run(db_session)
    result = await runner.tick(db_session, now=NOW + timedelta(minutes=30))
    assert result["reason"] == "rate_limited"

    install(monkeypatch, [say(findings_reply())])
    await request_run(db_session)
    assert (await runner.tick(db_session, now=NOW + timedelta(minutes=61)))["status"] == "ok"


async def test_no_run_during_maintenance_mode(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session)
    await make_alert(db_session)
    settings_row = await db_session.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db_session.add(settings_row)
    settings_row.maintenance_mode_enabled = True
    await request_run(db_session)
    install(monkeypatch, [])

    assert (await runner.tick(db_session, now=NOW))["reason"] == "maintenance"


async def test_identity_that_is_not_read_only_or_is_disabled_is_a_recorded_skip(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session, max_runs_per_hour=10)
    await make_alert(db_session)
    principal = await get_watch_principal(db_session)
    assert principal is not None
    writer = Role(name="writer", permissions=[{"action": "write", "resource_type": "subnet"}])
    db_session.add(writer)
    principal.groups[0].roles = [*principal.groups[0].roles, writer]
    await request_run(db_session)
    install(monkeypatch, [])

    assert (await runner.tick(db_session, now=NOW))["reason"] == "principal_not_read_only"

    principal = await get_watch_principal(db_session)
    assert principal is not None
    principal.groups[0].roles = [r for r in principal.groups[0].roles if r.name != "writer"]
    principal.is_active = False
    await request_run(db_session)
    result = await runner.tick(db_session, now=NOW + timedelta(minutes=1))
    assert result["reason"] == "principal_disabled"


# ── Failures ──────────────────────────────────────────────────────────


async def test_unparseable_reply_gets_one_repair_attempt(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session)
    alert = await make_alert(db_session)
    await request_run(db_session)
    llm = install(
        monkeypatch,
        [say("ns1 looks down to me."), say(findings_reply(draft(f"alert:{alert.id}")))],
    )

    await runner.tick(db_session, now=NOW)

    (run,) = await runs(db_session)
    assert run.state == "ok" and run.findings_opened == 1
    assert (run.tokens_in, run.rounds) == (20, 2)
    assert "could not be parsed" in llm.requests[1][1].messages[-1].content


async def test_repeated_failures_pause_watch_until_an_operator_resumes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session, max_runs_per_hour=10)
    await make_alert(db_session)

    for i in range(runner.MAX_CONSECUTIVE_FAILURES):
        install(monkeypatch, [say("not json"), say("still not json")])
        await request_run(db_session)
        result = await runner.tick(db_session, now=NOW + timedelta(minutes=i))
        assert result["status"] == "failed"

    last = (await runs(db_session))[-1]
    assert "could not be used" in (last.error or "")
    config = await runner.get_config(db_session)
    assert config.paused and config.paused_reason == "failures"
    assert config.paused_until is None
    assert "3 runs in a row failed" in config.paused_detail
    assert await findings(db_session) == []
    # It does not lift by itself, even the next day.
    assert (await runner.tick(db_session, now=NOW + timedelta(days=2)))["status"] == "paused"


async def test_a_good_run_resets_the_failure_count(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session, max_runs_per_hour=10, consecutive_failures=2)
    await make_alert(db_session)
    install(monkeypatch, [say(findings_reply())])
    await request_run(db_session)

    await runner.tick(db_session, now=NOW)

    assert (await runner.get_config(db_session)).consecutive_failures == 0


async def test_a_run_left_running_by_a_dead_worker_is_marked_failed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_provider(db_session)
    await arm(db_session)
    db_session.add(AIWatchRun(trigger="sweep", state="running", started_at=NOW - timedelta(hours=1)))
    await db_session.commit()
    install(monkeypatch, [])

    await runner.tick(db_session, now=NOW)

    (run,) = await runs(db_session)
    assert run.state == "failed" and "worker stopped" in (run.error or "")


def test_beat_task_is_scheduled_and_gated_on_the_module() -> None:
    from app.celery_app import celery_app
    from app.tasks.ai_watch import tick

    entry = celery_app.conf.beat_schedule["ai-watch-tick"]
    assert entry["task"] == "app.tasks.ai_watch.tick"
    assert tick.run.__module_gate__ == "ai.watch"
