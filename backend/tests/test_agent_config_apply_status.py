"""Agent config-apply status ingest + the ``agent_config_rejected`` alert (#882).

The failure this covers is specifically a *silent* one. When an agent cannot
apply a bundle it reverts to its last-known-good and keeps serving, so the
server's ``status`` stays ``active``, its health check passes and its
heartbeat keeps arriving on time — while the zone or scope the operator saved
is not live anywhere. These columns are the only place that divergence shows.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer, DNSServerGroup
from app.services.agents.config_apply import (
    FAILED_STATUSES,
    SEVERITY_BY_STATUS,
    STATUS_NO_PREVIOUS,
    STATUS_OK,
    STATUS_REVERT_FAILED,
    STATUS_REVERTED,
    apply_reported_status,
)
from app.services.alerts import _matching_agent_config_rejected_subjects

_RULE = SimpleNamespace(severity="warning")


def _row() -> SimpleNamespace:
    return SimpleNamespace(
        config_apply_status=None,
        config_apply_error=None,
        config_failed_etag=None,
        config_apply_at=None,
    )


def _report(row: object, payload: dict | None) -> None:
    apply_reported_status(row, payload, agent_kind="dns", server_id="s1")


# ── ingest ────────────────────────────────────────────────────────────────


def test_reverted_report_is_persisted() -> None:
    row = _row()
    _report(
        row,
        {
            "status": STATUS_REVERTED,
            "etag": "good",
            "failed_etag": "bad",
            "phase": "validate",
            "error": "named-checkconf failed: undefined acl 'trusted'",
        },
    )
    assert row.config_apply_status == STATUS_REVERTED
    assert row.config_failed_etag == "bad"
    assert "undefined acl" in row.config_apply_error
    assert row.config_apply_at is not None


def test_ok_clears_the_stale_failure_detail() -> None:
    """A green status next to last week's checkconf output is worse than
    nothing — the four columns move as a group."""
    row = _row()
    _report(row, {"status": STATUS_REVERTED, "failed_etag": "bad", "error": "boom"})
    _report(row, {"status": STATUS_OK, "etag": "fixed"})
    assert row.config_apply_status == STATUS_OK
    assert row.config_apply_error is None
    assert row.config_failed_etag is None


def test_empty_report_leaves_a_recorded_failure_alone() -> None:
    """A pre-#882 agent sends ``config: {}``.

    Treating that as ``ok`` would fabricate a verdict; NULLing the columns
    would erase a real failure recorded before a downgrade. Both are worse
    than leaving the last known answer in place.
    """
    row = _row()
    _report(row, {"status": STATUS_REVERTED, "failed_etag": "bad"})
    _report(row, {})
    _report(row, None)
    assert row.config_apply_status == STATUS_REVERTED
    assert row.config_failed_etag == "bad"


def test_unknown_status_is_ignored_not_guessed() -> None:
    """A newer agent than this control plane, or a corrupt payload."""
    row = _row()
    _report(row, {"status": STATUS_REVERTED, "failed_etag": "bad"})
    _report(row, {"status": "something_new"})
    assert row.config_apply_status == STATUS_REVERTED


def test_oversized_fields_are_clipped_to_the_columns() -> None:
    """The heartbeat is agent-supplied; the agent truncates, but a buggy or
    compromised one must not be able to write past the column width."""
    row = _row()
    _report(
        row,
        {
            "status": STATUS_REVERTED,
            "error": "x" * 9000,
            "failed_etag": "e" * 500,
        },
    )
    assert len(row.config_apply_error) == 2000
    assert len(row.config_failed_etag) == 128


def test_blank_strings_are_normalised_to_null() -> None:
    row = _row()
    _report(row, {"status": STATUS_REVERTED, "error": "   ", "failed_etag": ""})
    assert row.config_apply_error is None
    assert row.config_failed_etag is None


# ── alert matcher ─────────────────────────────────────────────────────────


async def _dns_server(db: AsyncSession, name: str, **kw: object) -> DNSServer:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    s = DNSServer(group_id=group.id, name=name, driver="bind9", host="10.0.0.53", port=53, **kw)
    db.add(s)
    await db.flush()
    return s


async def test_matcher_fires_on_a_reverted_agent(db_session: AsyncSession) -> None:
    await _dns_server(
        db_session,
        "ns-reverted",
        config_apply_status=STATUS_REVERTED,
        config_failed_etag="sha256:bad",
        config_apply_error="named-checkconf failed",
    )
    matches = await _matching_agent_config_rejected_subjects(db_session, _RULE)
    assert len(matches) == 1
    subject_id, display, message, severity = matches[0]
    # Subject ids are table-prefixed: one rule spans three tables and a
    # dns_server sharing a UUID with a dhcp_server must not collide.
    assert subject_id.startswith("dns_server:")
    assert "ns-reverted" in display
    assert "sha256:bad" in message
    assert "named-checkconf failed" in message
    assert severity == SEVERITY_BY_STATUS[STATUS_REVERTED]


async def test_a_partial_apply_does_not_claim_a_rollback(db_session: AsyncSession) -> None:
    """A PowerDNS agent that served every zone but one reports ``reverted``
    (there is no partial status) with a marked error. The alert used to say
    the server rolled back and was NOT serving what is saved, the opposite of
    what happened (ddi-pg's walk of #1280)."""
    from app.services.agents.config_apply import PARTIAL_APPLY_PREFIX, is_partial_apply

    error = (
        f"{PARTIAL_APPLY_PREFIX}the daemon refused 1 zone(s); every other zone is "
        "served: bad.test. create: HTTP 422 Duplicate record in RRset"
    )
    await _dns_server(
        db_session,
        "ns-partial",
        config_apply_status=STATUS_REVERTED,
        config_failed_etag="sha256:live",
        config_apply_error=error,
    )
    matches = await _matching_agent_config_rejected_subjects(db_session, _RULE)
    assert len(matches) == 1
    _subject, _display, message, severity = matches[0]
    assert "rolled back" not in message.replace("Nothing was rolled back", "")
    assert "NOT serving" not in message
    assert "applied the configuration" in message
    assert "bad.test." in message and "Duplicate record in RRset" in message
    assert PARTIAL_APPLY_PREFIX not in message
    assert "sha256:live" not in message, "the 'rejected' etag is the live one"
    assert severity == SEVERITY_BY_STATUS[STATUS_REVERTED]
    assert is_partial_apply(STATUS_REVERTED, error)
    assert not is_partial_apply(STATUS_REVERTED, "named-checkconf failed")
    assert not is_partial_apply("revert_failed", error)


async def test_matcher_ignores_ok_and_never_reported(db_session: AsyncSession) -> None:
    """NULL means the agent has never reported — a pre-#882 agent or an
    agentless driver with no apply loop. Firing on those would alarm every
    install on upgrade day and say nothing true."""
    await _dns_server(db_session, "ns-ok", config_apply_status=STATUS_OK)
    await _dns_server(db_session, "ns-silent")  # NULL
    assert await _matching_agent_config_rejected_subjects(db_session, _RULE) == []


async def test_severity_escalates_for_the_unrecoverable_states(
    db_session: AsyncSession,
) -> None:
    """``reverted`` is a warning: the daemon is up and answering, just not
    with the saved config. The other two mean it may not be answering."""
    await _dns_server(db_session, "ns-a", config_apply_status=STATUS_REVERT_FAILED)
    await _dns_server(db_session, "ns-b", config_apply_status=STATUS_NO_PREVIOUS)
    matches = await _matching_agent_config_rejected_subjects(db_session, _RULE)
    assert {m[3] for m in matches} == {"critical"}


async def test_matcher_spans_dhcp_servers_too(db_session: AsyncSession) -> None:
    db_session.add(
        DHCPServer(
            name="kea-1",
            driver="kea",
            host="10.0.0.67",
            config_apply_status=STATUS_REVERTED,
            config_failed_etag="sha256:bad",
        )
    )
    await db_session.flush()
    matches = await _matching_agent_config_rejected_subjects(db_session, _RULE)
    assert len(matches) == 1
    assert matches[0][0].startswith("dhcp_server:")


def test_failed_statuses_excludes_ok() -> None:
    """Every read surface filters on this set; ``ok`` leaking in would make
    the alert fire on every healthy server in the fleet."""
    assert STATUS_OK not in FAILED_STATUSES
    assert FAILED_STATUSES == {STATUS_REVERTED, STATUS_REVERT_FAILED, STATUS_NO_PREVIOUS}
