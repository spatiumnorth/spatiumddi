"""Forwarded audit events carry the read-side redaction (#2015).

#2009 / #2014 redacted an audit row's ``old_value`` / ``new_value`` /
``error_detail`` on READ — the audit API, the Audit page, the copilot. The
forwarding path (syslog / webhook / SMTP targets, and the typed-event
outbox) shipped the same content verbatim, so a writer's mistake reached a
SIEM with no backstop. These tests pin that every forwarded copy is
redacted, that the stored audit row is not, and that every target kind
reaches its transport through the one redacting chokepoint.
"""

from __future__ import annotations

import ast
import copy
import json
import pathlib
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.services import audit_forward as svc
from app.services.audit_redact import REDACTED

# A real Fernet token is random per call, so it is minted once at import and
# never appears in a test id.
_FERNET = Fernet(Fernet.generate_key()).encrypt(b"winrm-password-2015").decode()
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJhZG1pbi0yMDE1In0."
    "c2lnbmF0dXJlLW9mLXRoZS10b2tlbi0yMDE1"
)
_PASSWORD = "Pl41n-Passw0rd-2015"
_API_TOKEN = "spddi_tok_0123456789abcdef2015"
_TSIG_SECRET = "c2VjcmV0LXRzaWctbWF0ZXJpYWwtMjAxNQ=="
_PSK = "agent-psk-material-2015"

_SECRETS = (_FERNET, _JWT, _PASSWORD, _API_TOKEN, _TSIG_SECRET, _PSK)
_KEEP = "keepme-2015"


def _secret_old() -> dict[str, Any]:
    return {"password": _PASSWORD, "description": _KEEP}


def _secret_new() -> dict[str, Any]:
    return {
        "credentials_encrypted": _FERNET,
        "api_token": _API_TOKEN,
        "tsig_secret": _TSIG_SECRET,
        "agent_psk": _PSK,
        # A credential-shaped VALUE under a neutral key.
        "note": f"pasted {_FERNET}",
        "description": _KEEP,
        # The writers' convention survives: a flag, not the secret.
        "smtp_password_set": True,
    }


def _payload() -> dict[str, Any]:
    return {
        "id": "evt-2015",
        "timestamp": "2026-10-20T12:00:00+00:00",
        "action": "update",
        "resource_type": "dns_server",
        "resource_id": "s-1",
        "resource_display": "ns1",
        "result": "success",
        "user_id": "u-1",
        "user_display_name": "alice",
        "auth_source": "local",
        "changed_fields": ["credentials_encrypted"],
        "old_value": _secret_old(),
        "new_value": _secret_new(),
        "error_detail": f"upstream said Bearer {_JWT}",
    }


def _sent(mock: AsyncMock) -> str:
    """Everything a mocked transport was handed, as one string."""
    return json.dumps(
        [list(c.args) + sorted(c.kwargs.items()) for c in mock.await_args_list],
        default=str,
    )


def _assert_redacted(wire: str) -> None:
    for secret in _SECRETS:
        assert secret not in wire, "a secret reached the forwarding transport"
    # A format that carries the content at all must carry it redacted, not
    # dropped — the non-secret neighbour proves the content is there.
    if _KEEP in wire:
        assert REDACTED in wire


_SYSLOG_FORMATS = sorted([*svc._FORMATTERS, "json_lines"])  # noqa: SLF001
_WEBHOOK_FLAVORS = ["discord", "generic", "slack", "teams"]


def _target(kind: str, **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"name": f"t-{kind}", "kind": kind}
    if kind == "syslog":
        base.update(host="10.0.0.1", port=514, protocol="udp", facility=16, format="rfc5424_json")
    elif kind == "webhook":
        base.update(url="https://example.com/ingest", auth_header="", webhook_flavor="generic")
    elif kind == "smtp":
        base.update(
            smtp_host="mail.example.com",
            smtp_port=587,
            smtp_security="starttls",
            smtp_username="",
            smtp_password="",
            smtp_from_address="ddi@example.com",
            smtp_to_addresses=["ops@example.com"],
        )
    base.update(extra)
    return base


_TRANSPORT = {"syslog": "_send_syslog", "webhook": "_send_webhook", "smtp": "_send_smtp"}


async def _deliver(target: dict[str, Any], payload: dict[str, Any]) -> str:
    with patch.object(svc, _TRANSPORT[target["kind"]], new=AsyncMock()) as mock_send:
        outcome = await svc._deliver_to_target(target, payload)  # noqa: SLF001
    assert outcome == svc.DELIVERED
    assert mock_send.await_count == 1
    return _sent(mock_send)


# ── Every format / flavor / kind ──────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("fmt", _SYSLOG_FORMATS)
async def test_syslog_format_forwards_redacted(fmt: str) -> None:
    payload = _payload()
    before = copy.deepcopy(payload)
    wire = await _deliver(_target("syslog", format=fmt), payload)
    _assert_redacted(wire)
    # Redaction is on a copy: the caller's payload is untouched.
    assert payload == before


@pytest.mark.asyncio
@pytest.mark.parametrize("flavor", _WEBHOOK_FLAVORS)
async def test_webhook_flavor_forwards_redacted(flavor: str) -> None:
    payload = _payload()
    before = copy.deepcopy(payload)
    wire = await _deliver(_target("webhook", webhook_flavor=flavor), payload)
    _assert_redacted(wire)
    assert payload == before


@pytest.mark.asyncio
async def test_smtp_forwards_redacted() -> None:
    payload = _payload()
    before = copy.deepcopy(payload)
    _assert_redacted(await _deliver(_target("smtp"), payload))
    assert payload == before


@pytest.mark.asyncio
async def test_generic_webhook_keeps_structure_and_set_flags() -> None:
    """The generic webhook body is the payload itself — check the shape the
    collector receives: keys kept, secret values replaced, the writers'
    ``*_set: true`` flag left readable."""
    with patch.object(svc, "_send_webhook", new=AsyncMock()) as mock_send:
        await svc._deliver_to_target(_target("webhook"), _payload())  # noqa: SLF001
    body = mock_send.await_args.args[2]
    assert body["new_value"]["credentials_encrypted"] == REDACTED
    assert body["new_value"]["api_token"] == REDACTED
    assert body["new_value"]["tsig_secret"] == REDACTED
    assert body["new_value"]["agent_psk"] == REDACTED
    assert body["new_value"]["smtp_password_set"] is True
    assert body["new_value"]["description"] == _KEEP
    assert body["old_value"]["password"] == REDACTED
    assert _JWT not in body["error_detail"]
    assert body["changed_fields"] == ["credentials_encrypted"]


# ── Guard: every target kind goes through the chokepoint ──────────────


def test_every_target_kind_is_covered_by_these_tests() -> None:
    """A new target kind must be added to ``_TRANSPORT`` above, so the
    per-kind redaction test runs for it."""
    from app.api.v1.settings.router import _VALID_KINDS

    assert set(_VALID_KINDS) == set(_TRANSPORT)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", sorted(_TRANSPORT))
async def test_every_target_kind_forwards_redacted(kind: str) -> None:
    _assert_redacted(await _deliver(_target(kind), _payload()))


_SINKS = {
    "_send_syslog",
    "_send_webhook",
    "_send_smtp",
    "render_for_target",
    "_shape_webhook_body",
    "_smtp_subject_body",
}
_APP = pathlib.Path(__file__).resolve().parents[1] / "app"


def _called_name(node: ast.Call) -> str | None:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def test_transports_are_reached_only_through_the_redacting_chokepoint() -> None:
    """Every call into a forwarding renderer or transport, anywhere in
    ``app/``, sits inside ``audit_forward._deliver_to_target`` — and that
    function redacts before anything else. A new caller that renders or
    sends on its own would bypass the redaction; this fails it."""
    offenders: list[str] = []
    for path in sorted(_APP.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(_APP.parent).as_posix()
        for func in ast.walk(tree):
            if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            allowed = rel == "app/services/audit_forward.py" and func.name == "_deliver_to_target"
            for node in ast.walk(func):
                if isinstance(node, ast.Call) and _called_name(node) in _SINKS and not allowed:
                    offenders.append(f"{rel}:{node.lineno} {func.name} -> {_called_name(node)}")
    assert offenders == [], offenders

    src = (_APP / "services" / "audit_forward.py").read_text(encoding="utf-8")
    fn = next(
        n
        for n in ast.walk(ast.parse(src))
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "_deliver_to_target"
    )
    body = [
        n for n in fn.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))
    ]
    first = body[0]
    assert isinstance(first, ast.Assign) and isinstance(first.value, ast.Call)
    assert _called_name(first.value) == "redact_audit_payload"


# ── Stored row unchanged ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stored_audit_row_is_not_modified(db_session: AsyncSession) -> None:
    row = AuditLog(
        action="update",
        resource_type="dns_server",
        resource_id="s-2015",
        resource_display="ns1",
        user_display_name="alice",
        auth_source="local",
        result="failure",
        old_value=_secret_old(),
        new_value=_secret_new(),
        error_detail=f"Bearer {_JWT}",
        changed_fields=["credentials_encrypted"],
    )
    db_session.add(row)
    await db_session.commit()
    await db_session.refresh(row)

    from app.services.event_publisher import _serialize_audit

    for kind in sorted(_TRANSPORT):
        _assert_redacted(await _deliver(_target(kind), svc._serialize(row)))  # noqa: SLF001
    _assert_redacted(json.dumps(_serialize_audit(row, "dns_server.updated"), default=str))

    db_session.expire_all()
    stored = (
        await db_session.execute(select(AuditLog).where(AuditLog.resource_id == "s-2015"))
    ).scalar_one()
    assert stored.old_value == _secret_old()
    assert stored.new_value == _secret_new()
    assert stored.error_detail == f"Bearer {_JWT}"


# ── Typed-event outbox (webhook subscriptions) ────────────────────────


@pytest.mark.asyncio
async def test_event_outbox_delivery_redacts_rows_queued_unredacted() -> None:
    """An outbox row written before the fix still carries raw values; the
    send path redacts it too, and leaves the stored row unchanged."""
    import httpx

    from app.models.event_subscription import EventOutbox, EventSubscription
    from app.services import event_delivery

    raw = {
        "event_id": "e-2015",
        "event_type": "dns_server.updated",
        "old_value": _secret_old(),
        "new_value": _secret_new(),
    }
    row = EventOutbox(event_type="dns_server.updated", payload=copy.deepcopy(raw))
    sub = EventSubscription(url="https://example.com/hook", timeout_seconds=5)
    captured: list[bytes] = []

    async def _post(url: str, content: bytes, **_: Any) -> httpx.Response:
        captured.append(content)
        return httpx.Response(204)

    client = AsyncMock()
    client.post = _post
    with patch.object(event_delivery, "subscription_headers", return_value={}):
        status, err = await event_delivery._deliver_one(  # noqa: SLF001
            client, sub, row, "", "test"
        )
    assert (status, err) == (204, None)
    _assert_redacted(captured[0].decode())
    assert row.payload == raw


# ── Copilot backup-history tool ───────────────────────────────────────


@pytest.mark.asyncio
async def test_backup_audit_history_tool_redacts(db_session: AsyncSession) -> None:
    """``find_backup_audit_history`` returned ``new_value`` / ``error_detail``
    raw while ``get_audit_history`` redacted them (#2015)."""
    from app.core.security import hash_password
    from app.models.auth import User
    from app.services.ai.tools.backup import (
        FindBackupAuditHistoryArgs,
        find_backup_audit_history,
    )

    user = User(
        username="bk2015",
        email="bk2015@example.com",
        display_name="bk2015",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    db_session.add(
        AuditLog(
            action="backup_target_run_failed",
            resource_type="backup_target",
            resource_id="b-2015",
            resource_display="nas",
            user_display_name="system",
            auth_source="system",
            result="failure",
            new_value=_secret_new(),
            error_detail=f"auth failed: Bearer {_JWT}",
        )
    )
    await db_session.commit()

    rows = await find_backup_audit_history(db_session, user, FindBackupAuditHistoryArgs())
    _assert_redacted(json.dumps(rows, default=str))
    assert rows[0]["new_value"]["description"] == _KEEP


# ── Validator additions (#2015) ───────────────────────────────────────


def _deep_secret_payload() -> dict[str, Any]:
    """Secrets two and three levels down, and in a list of dicts."""
    return {
        **_payload(),
        "old_value": None,
        "new_value": {
            "name": _KEEP,
            "config": {
                "credentials": {"password": _PASSWORD, "region": "eu-1"},
                "nested": {"deeper": {"api_token": _API_TOKEN}},
                "targets": [
                    {"host": "a", "token": _JWT},
                    {"host": "b", "notes": f"key is {_FERNET}"},
                ],
            },
            "auth_pass_enc": "opaque-ciphertext-2015",
            "service_account_json": '{"project_id": "p", "type": "service_account"}',
        },
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", sorted(_TRANSPORT))
async def test_nested_secrets_are_redacted_and_original_is_not_mutated(kind: str) -> None:
    """``redact_audit_payload`` copies only the top level, so the nested
    redaction must build new containers rather than edit the caller's: the
    payload is serialized from the stored row and must leave it untouched."""
    payload = _deep_secret_payload()
    before = copy.deepcopy(payload)
    wire = await _deliver(_target(kind), payload)
    assert payload == before, "redaction mutated the caller's nested objects"
    for secret in (_PASSWORD, _API_TOKEN, _JWT, _FERNET):
        assert secret not in wire
    assert "opaque-ciphertext-2015" not in wire
    assert "service_account" not in wire or REDACTED in wire


def test_redact_payload_returns_fresh_nested_containers() -> None:
    from app.services.audit_redact import redact_audit_payload

    payload = _deep_secret_payload()
    out = redact_audit_payload(payload)
    cfg_in = payload["new_value"]["config"]
    cfg_out = out["new_value"]["config"]
    assert cfg_out is not cfg_in
    assert cfg_out["targets"] is not cfg_in["targets"]
    assert cfg_out["credentials"] == REDACTED
    assert cfg_out["nested"]["deeper"]["api_token"] == REDACTED
    assert cfg_out["targets"][0] == {"host": "a", "token": REDACTED}
    assert _FERNET not in cfg_out["targets"][1]["notes"]
    assert out["new_value"]["auth_pass_enc"] == REDACTED
    assert out["new_value"]["service_account_json"] == REDACTED
    assert out["new_value"]["name"] == _KEEP
    # The input still carries its secrets.
    assert cfg_in["credentials"]["password"] == _PASSWORD
    assert cfg_in["targets"][0]["token"] == _JWT
    # Idempotent.
    assert redact_audit_payload(out) == out


@pytest.mark.asyncio
async def test_event_outbox_signature_covers_the_redacted_body_sent() -> None:
    """A subscriber verifies the HMAC over the bytes it receives, so the
    signature must be computed over the redacted body, not the stored one."""
    import hashlib
    import hmac as _hmac

    import httpx

    from app.models.event_subscription import EventOutbox, EventSubscription
    from app.services import event_delivery

    row = EventOutbox(
        event_type="dns_server.updated",
        payload={"event_id": "e-sig", "old_value": _secret_old(), "new_value": _secret_new()},
    )
    sub = EventSubscription(url="https://example.com/hook", timeout_seconds=5)
    captured: list[tuple[bytes, dict[str, str]]] = []

    async def _post(url: str, content: bytes, headers: dict[str, str], **_: Any) -> httpx.Response:
        captured.append((content, headers))
        return httpx.Response(204)

    client = AsyncMock()
    client.post = _post
    secret = "sub-signing-secret-2015"
    with patch.object(event_delivery, "subscription_headers", return_value={}):
        status, err = await event_delivery._deliver_one(  # noqa: SLF001
            client, sub, row, secret, "test"
        )
    assert (status, err) == (204, None)
    body, headers = captured[0]
    _assert_redacted(body.decode())
    ts = headers["X-SpatiumDDI-Timestamp"]
    expected = _hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert headers["X-SpatiumDDI-Signature"] == f"sha256={expected}"
