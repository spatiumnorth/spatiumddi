"""Tests for the multi-target / multi-format audit forwarding.

Covers the interesting behaviors: per-format output shape, target
filtering (min_severity, resource_types), and multi-target fan-out.
Transport-level code (UDP / TCP / TLS sockets) is exercised by the
lowest-cost path — we assert the formatter output and mock the
network send, not the real wire.
"""

from __future__ import annotations

import json
import re
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.services import audit_forward as svc

# ── Payload helper ─────────────────────────────────────────────────


def _payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "evt-1",
        "timestamp": "2026-04-22T12:00:00+00:00",
        "action": "create",
        "resource_type": "dns_zone",
        "resource_id": "z-1",
        "resource_display": "example.com.",
        "result": "success",
        "user_id": "u-1",
        "user_display_name": "alice",
        "auth_source": "local",
        "changed_fields": ["name"],
        "old_value": None,
        "new_value": {"name": "example.com."},
    }
    base.update(overrides)
    return base


# ── Formatter unit tests ───────────────────────────────────────────


def test_rfc5424_json_has_pri_and_body():
    out = svc.render_for_target("rfc5424_json", facility=16, payload=_payload())
    assert out.startswith("<134>1 ")  # 16<<3 | 6 = 134 (facility=local0, sev=info)
    assert '"action":"create"' in out
    assert '"resource_type":"dns_zone"' in out


def test_rfc5424_cef_header_and_extensions():
    out = svc.render_for_target("rfc5424_cef", facility=16, payload=_payload())
    assert "CEF:0|SpatiumDDI|SpatiumDDI|1.0|dns_zone:create|example.com.|3" in out
    assert "act=create" in out
    assert "suser=alice" in out


def test_cef_denied_severity_maps_to_9():
    out = svc.render_for_target("rfc5424_cef", facility=16, payload=_payload(result="denied"))
    # "|9" after the name field
    assert "|example.com.|9|" in out


def test_leef_header_and_delimiter():
    out = svc.render_for_target("rfc5424_leef", facility=16, payload=_payload())
    assert "LEEF:2.0|SpatiumDDI|SpatiumDDI|1.0|dns_zone:create|^" in out
    # Fields separated by caret per header spec
    assert "^act=create" in out or "act=create^" in out


def test_rfc3164_prefix():
    out = svc.render_for_target("rfc3164", facility=16, payload=_payload())
    # <PRI>Mmm dd HH:MM:SS host tag: {json}
    assert out.startswith("<134>Apr 22 ")
    assert out.endswith('"new_value":{"name":"example.com."}}')


def test_json_lines_no_syslog_wrapper():
    out = svc.render_for_target("json_lines", facility=16, payload=_payload())
    assert out.startswith("{")
    assert out.endswith("}")
    assert "<134>" not in out


def test_unknown_format_falls_back_to_rfc5424_json():
    out = svc.render_for_target("bogus", facility=16, payload=_payload())
    assert out.startswith("<134>1 ")


# ── CEF / LEEF escaping ────────────────────────────────────────────


def test_cef_extension_escapes_equals_and_backslash():
    out = svc.render_for_target(
        "rfc5424_cef",
        facility=16,
        payload=_payload(user_display_name="bob=b\\ad"),
    )
    assert "suser=bob\\=b\\\\ad" in out


def test_cef_header_escapes_pipe():
    out = svc.render_for_target(
        "rfc5424_cef",
        facility=16,
        payload=_payload(resource_display="weird|name"),
    )
    # The pipe in the name field is escaped; extensions don't touch it.
    assert "|weird\\|name|" in out


# ── Filter tests ───────────────────────────────────────────────────


def test_min_severity_filter_blocks_lower():
    target = {
        "kind": "syslog",
        "min_severity": "error",
        "resource_types": None,
    }
    assert svc._target_accepts(target, _payload(result="success")) is False
    assert svc._target_accepts(target, _payload(result="error")) is True
    assert svc._target_accepts(target, _payload(result="denied")) is True


def test_resource_types_allowlist():
    target = {
        "kind": "syslog",
        "min_severity": None,
        "resource_types": ["dns_zone", "subnet"],
    }
    assert svc._target_accepts(target, _payload(resource_type="dns_zone")) is True
    assert svc._target_accepts(target, _payload(resource_type="dhcp_scope")) is False


def test_no_filter_accepts_everything():
    target = {"kind": "syslog", "min_severity": None, "resource_types": None}
    assert svc._target_accepts(target, _payload(result="success")) is True
    assert svc._target_accepts(target, _payload(result="denied")) is True


# ── Deliver fan-out ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_deliver_syslog_calls_send_syslog() -> None:
    target = {
        "name": "t",
        "kind": "syslog",
        "format": "rfc5424_json",
        "host": "10.0.0.1",
        "port": 514,
        "protocol": "udp",
        "facility": 16,
        "ca_cert_pem": None,
        "min_severity": None,
        "resource_types": None,
    }
    with patch.object(svc, "_send_syslog", new=AsyncMock()) as mock_send:
        await svc._deliver_to_target(target, _payload())
    assert mock_send.await_count == 1
    args = mock_send.await_args.args
    assert args[0] == "10.0.0.1"
    assert args[1] == 514
    assert args[2] == "udp"
    assert args[3].startswith("<134>1 ")


@pytest.mark.asyncio
async def test_deliver_webhook_calls_send_webhook() -> None:
    target = {
        "name": "wh",
        "kind": "webhook",
        "url": "https://example.com/ingest",
        "auth_header": "Bearer abc",
        "min_severity": None,
        "resource_types": None,
    }
    with patch.object(svc, "_send_webhook", new=AsyncMock()) as mock_wh:
        await svc._deliver_to_target(target, _payload())
    mock_wh.assert_awaited_once_with("https://example.com/ingest", "Bearer abc", _payload())


@pytest.mark.asyncio
async def test_filter_short_circuits_before_send() -> None:
    target = {
        "name": "quiet",
        "kind": "syslog",
        "format": "rfc5424_json",
        "host": "10.0.0.1",
        "port": 514,
        "protocol": "udp",
        "facility": 16,
        "ca_cert_pem": None,
        "min_severity": "denied",
        "resource_types": None,
    }
    with patch.object(svc, "_send_syslog", new=AsyncMock()) as mock_send:
        await svc._deliver_to_target(target, _payload(result="success"))
    mock_send.assert_not_awaited()


# ── CRUD API round-trip ────────────────────────────────────────────


async def _make_user(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


@pytest.mark.asyncio
async def test_crud_roundtrip(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    h = {"Authorization": f"Bearer {token}"}

    # Start empty
    r = await client.get("/api/v1/settings/audit-forward-targets", headers=h)
    assert r.status_code == 200, r.text
    assert r.json() == []

    # Create syslog
    body = {
        "name": "SIEM prod",
        "enabled": True,
        "kind": "syslog",
        "format": "rfc5424_cef",
        "host": "siem.example.com",
        "port": 6514,
        "protocol": "tls",
        "facility": 16,
    }
    r = await client.post("/api/v1/settings/audit-forward-targets", headers=h, json=body)
    assert r.status_code == 201, r.text
    created = r.json()
    target_id = created["id"]
    assert created["format"] == "rfc5424_cef"
    assert created["protocol"] == "tls"

    # List
    r = await client.get("/api/v1/settings/audit-forward-targets", headers=h)
    assert len(r.json()) == 1

    # Update
    r = await client.put(
        f"/api/v1/settings/audit-forward-targets/{target_id}",
        headers=h,
        json={**body, "port": 1514, "min_severity": "error"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["port"] == 1514
    assert r.json()["min_severity"] == "error"

    # Delete
    r = await client.delete(f"/api/v1/settings/audit-forward-targets/{target_id}", headers=h)
    assert r.status_code == 204
    r = await client.get("/api/v1/settings/audit-forward-targets", headers=h)
    assert r.json() == []


@pytest.mark.asyncio
async def test_crud_writes_audit_log_without_secrets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#1584: create/update/delete of an audit-forward target must each
    write an audit_log row, and the row must never carry the webhook
    URL, auth header or SMTP password — only ``*_set`` booleans."""
    _, token = await _make_user(db_session)
    h = {"Authorization": f"Bearer {token}"}

    body = {
        "name": "SIEM webhook",
        "enabled": True,
        "kind": "webhook",
        "format": "json_lines",
        "url": "https://hooks.example.com/ingest/secret-path",
        "auth_header": "Bearer <redacted>",
    }
    r = await client.post("/api/v1/settings/audit-forward-targets", headers=h, json=body)
    assert r.status_code == 201, r.text
    target_id = r.json()["id"]

    r = await client.put(
        f"/api/v1/settings/audit-forward-targets/{target_id}",
        headers=h,
        json={**body, "enabled": False},
    )
    assert r.status_code == 200, r.text

    r = await client.delete(f"/api/v1/settings/audit-forward-targets/{target_id}", headers=h)
    assert r.status_code == 204

    rows = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(
                    AuditLog.resource_type == "audit_forward_target",
                    AuditLog.resource_id == target_id,
                )
                .order_by(AuditLog.seq)
            )
        )
        .scalars()
        .all()
    )
    assert [row.action for row in rows] == ["create", "update", "delete"]
    create_row, update_row, delete_row = rows
    assert create_row.new_value is not None
    assert create_row.new_value["url_set"] is True
    assert create_row.new_value["auth_header_set"] is True
    assert create_row.new_value["smtp_password_set"] is False
    assert update_row.old_value is not None and update_row.new_value is not None
    assert update_row.old_value["enabled"] is True
    assert update_row.new_value["enabled"] is False
    assert delete_row.old_value is not None
    assert delete_row.new_value is None
    blob = json.dumps([row.old_value for row in rows] + [row.new_value for row in rows])
    assert "hooks.example.com" not in blob
    assert "topsecret" not in blob


@pytest.mark.asyncio
async def test_invalid_format_rejected(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    r = await client.post(
        "/api/v1/settings/audit-forward-targets",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "bad",
            "enabled": True,
            "kind": "syslog",
            "format": "not-a-format",
            "host": "x",
        },
    )
    assert r.status_code == 422


# Fallback / preempt tests for ``_load_targets`` are deliberately
# omitted: the service opens its own ``AsyncSessionLocal`` which binds
# to the app DB, not the fixture-managed test DB. The two-session
# split gets in the way of a clean assertion here. The behavior is
# exercised in real upgrades and covered at the CRUD-roundtrip level
# (a row written through the API shows up in a subsequent GET).


# ── Alert / digest payload shapes (issue #1031) ────────────────────
#
# Three payload shapes go through ``_deliver_to_target``, and until #1031
# only the audit one was handled: alerts and digests carry ``severity`` +
# ``fired_at`` where an audit row carries ``result`` + ``timestamp``.
#
# These pin the WIRE OUTPUT rather than the helpers, because every one of
# the four symptoms was visible only there — a PRI that said
# "informational" for a critical alert, a CEF severity of 3, a gate that
# dropped the event, and a KeyError that meant nothing was sent at all.


def _alert(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "kind": "alert",
        "rule_id": "rule-1",
        "rule_name": "Appliance storage degraded",
        "rule_type": "appliance_storage_degraded",
        "severity": "critical",
        "fired_at": "2026-04-22T12:00:00+00:00",
        "subject_type": "appliance",
        "subject_id": "ap-1",
        "subject_display": "ddi1",
        "message": "array root_a is degraded (1 of 2 members)",
    }
    base.update(overrides)
    return base


def _digest(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "kind": "digest",
        "title": "SpatiumDDI Daily Operator Digest",
        "severity": "info",
        "resource_type": "ai.digest",
        "fired_at": "2026-04-22T06:00:00+00:00",
        "message": "all quiet",
        "summary": "all quiet",
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize("fmt", ["rfc5424_json", "rfc5424_cef", "rfc5424_leef", "rfc3164"])
def test_alert_renders_in_every_syslog_format(fmt: str) -> None:
    """The regression that mattered most: three of these raised
    ``KeyError: 'timestamp'``, so an alert to a syslog target — on the
    DEFAULT format — was never delivered, and ``alerts._deliver``
    swallowed the exception into a log line."""
    out = svc.render_for_target(fmt, facility=16, payload=_alert())
    assert out


@pytest.mark.parametrize("fmt", ["rfc5424_json", "rfc5424_cef", "rfc5424_leef", "rfc3164"])
def test_digest_renders_in_every_syslog_format(fmt: str) -> None:
    out = svc.render_for_target(fmt, facility=16, payload=_digest())
    assert out


def test_alert_severity_reaches_the_syslog_pri() -> None:
    # facility 16 << 3 = 128; + 2 crit / 4 warning / 6 info.
    assert svc.render_for_target(
        "rfc5424_json", facility=16, payload=_alert(severity="critical")
    ).startswith("<130>1 ")
    assert svc.render_for_target(
        "rfc5424_json", facility=16, payload=_alert(severity="warning")
    ).startswith("<132>1 ")
    assert svc.render_for_target(
        "rfc5424_json", facility=16, payload=_alert(severity="info")
    ).startswith("<134>1 ")


def test_audit_syslog_severities_are_unchanged() -> None:
    """The audit mappings must not move — an existing collector already
    indexes those PRI values."""
    for result, pri in (("success", "<134>"), ("failed", "<131>"), ("denied", "<132>")):
        out = svc.render_for_target("rfc5424_json", facility=16, payload=_payload(result=result))
        assert out.startswith(pri + "1 "), result


def test_alert_syslog_timestamp_comes_from_fired_at() -> None:
    """Not the wall clock. ``rfc3164`` rendered without raising before
    the fix, but stamped 'now' — so a delayed or replayed alert was
    filed under the wrong minute."""
    out = svc.render_for_target("rfc3164", facility=16, payload=_alert())
    assert out.startswith("<130>Apr 22 12:00:00 ")


def test_alert_cef_carries_the_rule_not_the_word_audit() -> None:
    out = svc.render_for_target("rfc5424_cef", facility=16, payload=_alert())
    assert "|appliance_storage_degraded|Appliance storage degraded|9|" in out
    assert "cs5=Appliance storage degraded" in out
    assert "cs6=ddi1" in out


def test_alert_leef_carries_the_rule_not_the_word_audit() -> None:
    out = svc.render_for_target("rfc5424_leef", facility=16, payload=_alert())
    assert "|appliance_storage_degraded|^" in out
    # ``sev`` is numeric — see test_leef_severity_is_numeric_not_a_word.
    assert "sev=9" in out
    assert "ruleName=Appliance storage degraded" in out


def test_min_severity_no_longer_drops_every_alert() -> None:
    """The filed bug. A target set to anything above ``info`` dropped the
    lot, criticals included, because alerts bucketed to ``info``."""
    for threshold in ("info", "warn", "error", "denied"):
        target = {"kind": "syslog", "min_severity": threshold, "resource_types": None}
        assert svc._target_accepts(target, _alert(severity="critical")) is True, threshold


def test_min_severity_still_filters_alerts_it_should() -> None:
    target = {"kind": "syslog", "min_severity": "error", "resource_types": None}
    assert svc._target_accepts(target, _alert(severity="info")) is False
    assert svc._target_accepts(target, _alert(severity="warning")) is False
    assert svc._target_accepts(target, _alert(severity="critical")) is True


def test_resource_types_allowlist_matches_an_alert_subject() -> None:
    """``subject_type`` is the same vocabulary as ``resource_type``; with
    no fallback a target carrying an allowlist dropped every alert."""
    target = {"kind": "syslog", "min_severity": None, "resource_types": ["appliance"]}
    assert svc._target_accepts(target, _alert()) is True
    assert svc._target_accepts(target, _alert(subject_type="dns_zone")) is False


def test_unrankable_severity_fails_open() -> None:
    """A severity string we cannot rank says nothing about whether the
    operator wanted the event; silently swallowing it is the bug."""
    target = {"kind": "syslog", "min_severity": "error", "resource_types": None}
    assert svc._target_accepts(target, _alert(severity="catastrophic")) is True


# ── LEEF conformance + the namespaced subject (code-review follow-ups)


def test_leef_severity_is_numeric_not_a_word() -> None:
    """LEEF 2.0 defines ``sev`` as an integer 1-10. A word is not a value
    QRadar can map, so it leaves the event at default severity — the same
    "the wire says informational" defect fixed for the PRI and for CEF,
    reintroduced by the field that was added to fix them."""
    out = svc.render_for_target("rfc5424_leef", facility=16, payload=_alert())
    assert "sev=9" in out
    assert "sev=critical" not in out
    warn = svc.render_for_target("rfc5424_leef", facility=16, payload=_alert(severity="warning"))
    assert "sev=6" in warn
    info = svc.render_for_target("rfc5424_leef", facility=16, payload=_digest())
    assert "sev=3" in info


def test_leef_severity_matches_cef_for_audit_rows() -> None:
    """One numeric map serves both renderers, so they cannot disagree
    about how severe the same event was."""
    for result, expected in (("success", 3), ("failed", 6), ("denied", 9)):
        payload = _payload(result=result)
        leef = svc.render_for_target("rfc5424_leef", facility=16, payload=payload)
        cef = svc.render_for_target("rfc5424_cef", facility=16, payload=payload)
        assert f"sev={expected}" in leef, result
        assert f"|{expected}|" in cef, result


def test_leef_escapes_its_own_delimiter() -> None:
    """``_render_leef`` declares ``^`` as the delimiter, not LEEF's
    default tab — so ``^`` is what has to be escaped, and it was not. An
    unescaped one splits the record and every field after it is lost.
    Free-form text (an alert message, the AI digest's generated summary)
    now flows through here, which is what makes it reachable."""
    out = svc.render_for_target(
        "rfc5424_leef",
        facility=16,
        payload=_alert(message="array ^ degraded", subject_display="node^1"),
    )
    body = out.split("|^|", 1)[1]
    # Split on UNESCAPED delimiters only — which is what a conforming
    # parser does, and the thing being asserted. Every resulting field
    # must be one key=value; an unescaped ``^`` inside a value produces
    # a fragment with no "=" in it.
    for field in re.split(r"(?<!\\)\^", body):
        assert "=" in field, f"unescaped delimiter split the record: {field!r}"
    assert "msg=array \\^ degraded" in out
    assert "subject=node\\^1" in out
    # The header's DelimiterChar DECLARES the delimiter and must stay
    # unescaped, or a parser reads it as backslash-caret.
    assert "|^|" in out
    assert "|\\^|" not in out


def test_cef_audit_severities_are_unchanged() -> None:
    """Sharing the numeric map with LEEF must not have moved CEF."""
    assert "|example.com.|3|" in svc.render_for_target(
        "rfc5424_cef", facility=16, payload=_payload(result="success")
    )
    assert "|example.com.|9|" in svc.render_for_target(
        "rfc5424_cef", facility=16, payload=_payload(result="denied")
    )


def test_resource_types_allowlist_matches_a_namespaced_subject() -> None:
    """``compliance_change`` reports ``subject_type="audit:<type>"``
    because its subject IS an audited resource. Matching only the raw
    string left exactly those alerts failing every allowlist — the bug
    the fallback exists to fix, surviving in the one rule that namespaces
    its subject."""
    target = {"kind": "syslog", "min_severity": None, "resource_types": ["dns_zone"]}
    assert svc._target_accepts(target, _alert(subject_type="audit:dns_zone")) is True
    assert svc._target_accepts(target, _alert(subject_type="audit:subnet")) is False
    # The bare form still matches, and an unrelated one still does not.
    assert svc._target_accepts(target, _alert(subject_type="dns_zone")) is True
    assert svc._target_accepts(target, _alert(subject_type="appliance")) is False
