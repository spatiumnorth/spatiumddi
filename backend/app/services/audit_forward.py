"""External forwarding for audit-log events.

Subscribes to the SQLAlchemy ``after_commit`` lifecycle on every async
session and, for each successfully committed ``AuditLog`` row, fans
the event out to every enabled ``AuditForwardTarget`` using that
target's configured output format and transport.

Supported output formats (syslog kind):

* ``rfc5424_json``  RFC 5424 envelope, JSON body. Default — most
  modern SIEMs (Splunk, Elastic, Graylog) auto-parse embedded JSON.
* ``rfc5424_cef``   RFC 5424 envelope, CEF 0 body. ArcSight + many
  commercial SIEMs.
* ``rfc5424_leef``  RFC 5424 envelope, LEEF 2.0 body. IBM QRadar.
* ``rfc3164``       Legacy BSD syslog — short PRI + timestamp + host
  + tag. For collectors that don't speak 5424.
* ``json_lines``    No syslog wrapper, just one JSON object per line.
  For raw TCP/UDP inputs on Logstash / Fluentd / Vector.

Webhook targets always deliver compact JSON (the HTTP body); the
``format`` column is ignored for ``kind="webhook"``.

Design notes:

* **Never blocks the commit.** The hook collects audit rows inside
  ``after_flush`` while they still have IDs, then schedules delivery
  in ``after_commit`` via ``after_commit_dispatch.dispatch`` — the
  request loop in the api, a per-process background loop in a Celery
  worker, where the task's own loop cancelled it on return (#1168).
* **One task per target per row.** A dead collector isolates to its
  own target; others still see the event.
* **Legacy flat-config fallback.** When no ``AuditForwardTarget``
  rows exist (fresh install + operator hasn't migrated), we still
  read the flat ``audit_forward_*`` columns on ``PlatformSettings``
  so existing deployments keep working through the upgrade.

See ``docs/OBSERVABILITY.md`` for the operator-facing view.
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings as _app_settings
from app.models.audit import AuditLog
from app.models.audit_forward import AuditForwardTarget
from app.models.settings import PlatformSettings
from app.services.after_commit_dispatch import dispatch

logger = structlog.get_logger(__name__)

# ── RFC 5424 constants ─────────────────────────────────────────────────────

# Severity: 0=emerg, 1=alert, 2=crit, 3=err, 4=warn, 5=notice, 6=info, 7=debug
_SEVERITY_SUCCESS = 6  # info
_SEVERITY_DENIED = 4  # warning
_SEVERITY_FAILED = 3  # err
_SEVERITY_CRITICAL = 2  # crit — alert severity "critical" only (#1031)

_APP_NAME = "spatiumddi"
_MSG_ID = "AUDIT"

_SINGLETON_ID = 1

_PENDING_ATTR = "__spatium_audit_forward_pending__"

# min_severity filter — higher rank means more severe. Keeps the
# filter logic a single numeric compare.
#
# TWO vocabularies land here, and #1031 was filed because only one of
# them was ranked. Audit rows bucket to ``info`` / ``warn`` / ``error`` /
# ``denied`` (the values a target's ``min_severity`` may be set to);
# alert + digest events carry ``info`` / ``warning`` / ``critical``
# directly. Both are ranked on ONE scale so the gate is still a single
# compare and an operator's threshold means the same thing whichever
# stream the event came from.
#
# ``critical`` sits at the TOP of the scale, level with ``denied``,
# deliberately: ``denied`` is the strictest threshold an operator can
# select, and a threshold that silently opts you out of the most severe
# alerts is the exact defect #1031 is about — just narrower.
_SEVERITY_RANK = {
    "info": 0,
    "warn": 1,
    "warning": 1,
    "error": 2,
    "denied": 3,
    "critical": 3,
}


# ── Event payload ──────────────────────────────────────────────────────────


def _serialize(row: AuditLog) -> dict[str, Any]:
    """Neutral JSON shape — consumed by every formatter + the webhook."""
    ts = getattr(row, "timestamp", None) or datetime.now(UTC)
    return {
        "id": str(row.id),
        "timestamp": ts.isoformat(),
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "resource_display": row.resource_display,
        "result": row.result,
        "user_id": str(row.user_id) if row.user_id else None,
        "user_display_name": row.user_display_name,
        "auth_source": row.auth_source,
        "changed_fields": row.changed_fields or [],
        "old_value": row.old_value,
        "new_value": row.new_value,
    }


def _severity_bucket(result: str | None) -> str:
    r = (result or "").lower()
    if r == "denied":
        return "denied"
    if r in ("failed", "error"):
        return "error"
    return "info"


# ── Payload-shape adapters (issue #1031) ───────────────────────────────────
#
# THREE payload shapes reach the renderers below, and every one of them is
# delivered by the same ``_deliver_to_target``:
#
#   * audit rows   — ``timestamp`` + ``result`` + ``action`` + ``resource_*``
#   * alert events — ``fired_at``  + ``severity`` + ``rule_name`` + ``message``
#   * AI digests   — ``fired_at``  + ``severity`` + ``title`` + ``summary``
#
# Everything here used to read the AUDIT keys unconditionally, so the other
# two were mis-rendered in four separate ways at once: dropped by a
# ``min_severity`` gate that bucketed them all to ``info``, stamped with a
# syslog PRI that said "informational" on the wire whatever the alert
# actually was, given CEF severity 3 for the same reason, and — for the
# three RFC 5424 formats, ``rfc5424_json`` among them, which is the
# DEFAULT — raised ``KeyError: 'timestamp'`` and never delivered at all.
#
# The last one hid the other three: ``alerts._deliver`` catches the
# exception per-target and logs ``alert_deliver_failed``, so a syslog
# target simply received nothing. And the "Test target" button sends an
# audit-shaped payload with ``min_severity`` forced to None, so the probe
# was green on a target that could not carry a single real alert.
#
# These adapters are the one place the shapes are reconciled; every
# renderer and the delivery gate go through them.


def _payload_severity(payload: dict[str, Any]) -> str:
    """The event's severity as a string, whichever shape it arrived in.

    Audit rows expose ``result`` (which we map via ``_severity_bucket``);
    alert + digest payloads carry ``severity`` directly (``info`` /
    ``warning`` / ``critical``).
    """
    sev = payload.get("severity")
    if isinstance(sev, str) and sev:
        return sev.lower()
    return _severity_bucket(payload.get("result"))


def _payload_timestamp(payload: dict[str, Any]) -> str:
    """The event time, as an ISO-8601 string.

    Audit rows carry ``timestamp``; alerts and digests carry ``fired_at``.
    Falls back to now() rather than raising: a syslog line stamped a
    millisecond late is a far better outcome than a delivery that fails,
    which is what the bare ``payload["timestamp"]`` lookup used to do.
    """
    for key in ("timestamp", "fired_at"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return datetime.now(UTC).isoformat()


#: CEF (0-10) and LEEF (1-10) both want a NUMBER. 3/6/9 is valid in
#: both, and the audit half of it is exactly what ``_render_cef`` has
#: always emitted — so sharing one map adds LEEF's missing ``sev``
#: without moving a single existing CEF line.
_SCALED_SEVERITY = {
    "info": 3,
    "warn": 6,
    "warning": 6,
    "error": 6,
    "denied": 9,
    "critical": 9,
}


def _payload_scaled_severity(payload: dict[str, Any]) -> int:
    """CEF / LEEF numeric severity.

    Defaults to 6 (medium) rather than 3 for an unrecognised value,
    because reporting an unknown severity as *informational* is how a
    real event gets filtered out of a SIEM.
    """
    return _SCALED_SEVERITY.get(_payload_severity(payload), 6)


def _payload_syslog_severity(payload: dict[str, Any]) -> int:
    """RFC 5424 numeric severity for the PRI field.

    The audit mappings are unchanged byte-for-byte (a change there would
    move every line an existing collector already indexes); the alert
    severities are added alongside.
    """
    sev = _payload_severity(payload)
    if sev == "critical":
        return _SEVERITY_CRITICAL
    if sev in ("denied", "warning", "warn"):
        return _SEVERITY_DENIED
    if sev == "error":
        return _SEVERITY_FAILED
    return _SEVERITY_SUCCESS


def _hostname() -> str:
    return socket.gethostname() or "spatiumddi"


# ── Formatters ─────────────────────────────────────────────────────────────


def _render_rfc5424_prefix(facility: int, severity: int, ts: str) -> str:
    pri = (facility << 3) | severity
    return f"<{pri}>1 {ts} {_hostname()} {_APP_NAME} - {_MSG_ID} -"


def _render_rfc5424_json(facility: int, payload: dict[str, Any]) -> str:
    severity = _payload_syslog_severity(payload)
    prefix = _render_rfc5424_prefix(facility, severity, _payload_timestamp(payload))
    return prefix + " " + json.dumps(payload, separators=(",", ":"), default=str)


def _cef_escape(s: Any) -> str:
    """Escape a CEF extension value.

    CEF reserves ``\\`` and ``=`` in extension values and ``|`` in the
    header pipe-separated fields. Per the spec any value containing
    those characters must be backslash-escaped.
    """
    v = "" if s is None else str(s)
    return v.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def _cef_header_escape(s: Any) -> str:
    v = "" if s is None else str(s)
    return v.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _render_cef(payload: dict[str, Any]) -> str:
    """ArcSight CEF 0 body.

    Fixed header: ``CEF:0|Vendor|Product|Version|SignatureID|Name|Severity``
    then key=value extension pairs. CEF severity is 0-10; we map our
    three audit buckets to 3/6/9 for info/error/denied, and the alert
    severities alongside them (#1031).
    """
    sev = _payload_scaled_severity(payload)
    action = payload.get("action") or "audit"
    resource_type = payload.get("resource_type") or ""
    signature = f"{resource_type}:{action}" if resource_type else action
    name = payload.get("resource_display") or signature
    # Alert + digest events carry none of the audit identifiers, so
    # without this they rendered as a content-free ``…|audit|audit|3|``
    # line: two different alerts were indistinguishable in the SIEM.
    if payload.get("kind") in ("alert", "digest"):
        signature = str(payload.get("rule_type") or payload.get("kind") or "alert")
        name = str(
            payload.get("rule_name") or payload.get("title") or payload.get("kind") or "alert"
        )

    header = "|".join(
        _cef_header_escape(x)
        for x in [
            "CEF:0",
            "SpatiumDDI",
            "SpatiumDDI",
            "1.0",
            signature,
            name,
            str(sev),
        ]
    )

    ext_fields: list[tuple[str, Any]] = [
        ("act", payload.get("action")),
        ("outcome", payload.get("result")),
        ("suser", payload.get("user_display_name")),
        ("duser", payload.get("resource_display")),
        ("cs1Label", "resource_type"),
        ("cs1", payload.get("resource_type")),
        ("cs2Label", "resource_id"),
        ("cs2", payload.get("resource_id")),
        ("cs3Label", "auth_source"),
        ("cs3", payload.get("auth_source")),
        ("cs4Label", "changed_fields"),
        ("cs4", ",".join(payload.get("changed_fields") or [])),
        ("externalId", payload.get("id") or payload.get("rule_id")),
        ("rt", _payload_timestamp(payload)),
        # Alert / digest fields. Empty on an audit row, so they drop out
        # of the extension list below exactly like the audit fields do on
        # an alert.
        ("cs5Label", "rule_name"),
        ("cs5", payload.get("rule_name") or payload.get("title")),
        ("cs6Label", "subject"),
        ("cs6", payload.get("subject_display")),
        ("msg", payload.get("message")),
    ]
    ext = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext_fields if v not in (None, ""))
    return f"{header}|{ext}"


def _render_rfc5424_cef(facility: int, payload: dict[str, Any]) -> str:
    severity = _payload_syslog_severity(payload)
    prefix = _render_rfc5424_prefix(facility, severity, _payload_timestamp(payload))
    return prefix + " " + _render_cef(payload)


#: Declared in the LEEF header's DelimiterChar field. ``^`` rather than
#: the LEEF default of tab, because tab gets mangled over UDP on some
#: relays — which is why ``_leef_escape`` must escape THIS character.
_LEEF_DELIMITER = "^"


def _leef_escape(s: Any) -> str:
    v = "" if s is None else str(s)
    # ``_render_leef`` declares ``^`` as its delimiter (DelimiterChar
    # ``5e``), NOT the LEEF default of tab — so ``^`` is the character
    # that must be escaped here, and it was not. An unescaped one inside
    # a value splits the record and every field after it is lost. That
    # got sharply more likely when free-form text started coming through
    # (``msg`` carries an alert message, or the AI digest's generated
    # summary), which is why it is fixed alongside them. Tabs are still
    # flattened, since the default delimiter is what a relay may
    # re-parse against.
    return (
        v.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace(_LEEF_DELIMITER, "\\" + _LEEF_DELIMITER)
        .replace("\t", " ")
        .replace("\n", " ")
    )


def _render_leef(payload: dict[str, Any]) -> str:
    """IBM QRadar LEEF 2.0 body.

    ``LEEF:2.0|Vendor|Product|Version|EventID|DelimiterChar|key=val<delim>…``
    We use ``^`` as the delimiter (DelimiterChar hex ``5e``) because tab
    gets mangled over UDP on some relays.
    """
    action = payload.get("action") or "audit"
    resource_type = payload.get("resource_type") or ""
    event_id = f"{resource_type}:{action}" if resource_type else action
    if payload.get("kind") in ("alert", "digest"):
        event_id = str(payload.get("rule_type") or payload.get("kind") or "alert")

    # The DelimiterChar field DECLARES the delimiter; it is a header
    # control character, not a value, so it must not go through
    # ``_leef_escape`` — which now escapes ``^`` and would emit ``\^``,
    # telling a parser the delimiter is backslash-caret. Caught by the
    # pre-existing header test the moment the escape was added.
    header = (
        "|".join(_leef_escape(x) for x in ["LEEF:2.0", "SpatiumDDI", "SpatiumDDI", "1.0", event_id])
        + "|"
        + _LEEF_DELIMITER
    )

    fields: list[tuple[str, Any]] = [
        ("devTime", _payload_timestamp(payload)),
        # NUMERIC. LEEF 2.0 defines ``sev`` as an integer 1-10, so a
        # word here ("critical") is not a value QRadar can map — it
        # leaves the event at default severity, which is the same
        # "the wire says informational" defect being fixed for the
        # syslog PRI and for CEF.
        ("sev", _payload_scaled_severity(payload)),
        ("devTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"),
        ("act", payload.get("action")),
        ("outcome", payload.get("result")),
        ("usrName", payload.get("user_display_name")),
        ("userId", payload.get("user_id")),
        ("resourceType", payload.get("resource_type")),
        ("resourceId", payload.get("resource_id")),
        ("resource", payload.get("resource_display")),
        ("authSource", payload.get("auth_source")),
        ("changedFields", ",".join(payload.get("changed_fields") or [])),
        ("externalId", payload.get("id") or payload.get("rule_id")),
        ("ruleName", payload.get("rule_name") or payload.get("title")),
        ("subject", payload.get("subject_display")),
        ("msg", payload.get("message")),
    ]
    body = _LEEF_DELIMITER.join(f"{k}={_leef_escape(v)}" for k, v in fields if v not in (None, ""))
    return f"{header}|{body}"


def _render_rfc5424_leef(facility: int, payload: dict[str, Any]) -> str:
    severity = _payload_syslog_severity(payload)
    prefix = _render_rfc5424_prefix(facility, severity, _payload_timestamp(payload))
    return prefix + " " + _render_leef(payload)


def _render_rfc3164(facility: int, payload: dict[str, Any]) -> str:
    """Legacy BSD syslog per RFC 3164.

    ``<PRI>Mmm dd HH:MM:SS host tag: msg``. Month/day/time are in the
    local system's convention — no year, no timezone. Body is compact
    JSON (keeps parsing simple for legacy collectors that index via
    regex).
    """
    severity = _payload_syslog_severity(payload)
    pri = (facility << 3) | severity
    try:
        ts = datetime.fromisoformat(_payload_timestamp(payload))
    except (KeyError, ValueError, TypeError):
        ts = datetime.now(UTC)
    # RFC 3164: single-digit days get a leading space, not zero.
    day = f"{ts.day:>2}"
    stamp = ts.strftime(f"%b {day} %H:%M:%S")
    body = json.dumps(payload, separators=(",", ":"), default=str)
    return f"<{pri}>{stamp} {_hostname()} {_APP_NAME}: {body}"


def _render_json_lines(payload: dict[str, Any]) -> str:
    """Bare JSON — no syslog framing. For raw TCP/UDP Logstash / Vector."""
    return json.dumps(payload, separators=(",", ":"), default=str)


_FORMATTERS = {
    "rfc5424_json": _render_rfc5424_json,
    "rfc5424_cef": _render_rfc5424_cef,
    "rfc5424_leef": _render_rfc5424_leef,
    "rfc3164": _render_rfc3164,
    # json_lines takes no facility — adapter below.
}


def render_for_target(fmt: str, facility: int, payload: dict[str, Any]) -> str:
    if fmt == "json_lines":
        return _render_json_lines(payload)
    formatter = _FORMATTERS.get(fmt)
    if formatter is None:
        formatter = _FORMATTERS["rfc5424_json"]
    return formatter(facility, payload)


# Legacy single-format helper — kept so alerts.py doesn't break mid-refactor.
def _render_rfc5424(facility: int, row: Any, payload: dict[str, Any]) -> str:
    return _render_rfc5424_json(facility, payload)


# ── Transport ──────────────────────────────────────────────────────────────


async def _send_syslog(
    host: str,
    port: int,
    protocol: str,
    message: str,
    ca_cert_pem: str | None = None,
) -> None:
    if protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto((message + "\n").encode("utf-8"), (host, port))
        return

    ssl_ctx: ssl.SSLContext | None = None
    if protocol == "tls":
        if ca_cert_pem:
            ssl_ctx = ssl.create_default_context(cadata=ca_cert_pem)
        else:
            ssl_ctx = ssl.create_default_context()

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ssl_ctx),
        timeout=5.0,
    )
    try:
        writer.write((message + "\n").encode("utf-8"))
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        del reader


async def _send_webhook(url: str, auth_header: str, payload: dict[str, Any]) -> None:
    headers = {"Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        if resp.status_code >= 300:
            logger.warning(
                "audit_forward_webhook_non2xx",
                status=resp.status_code,
                body_preview=resp.text[:200],
            )


# ── Chat-flavor webhook formatters (Slack / Teams / Discord) ───────────────
#
# Each platform's incoming-webhook URL accepts JSON in a slightly
# different shape. Operators paste the same incoming-webhook URL the
# platform issued them; we shape the body at send time based on the
# target's ``webhook_flavor``. ``generic`` keeps the original raw
# payload for downstream automation that doesn't speak chat-card JSON.

_SEVERITY_COLOURS = {
    # Generic decimal RGB colours used by Discord embeds.
    "info": 0x4FACFE,  # cyan-blue
    "warn": 0xF59E0B,  # amber
    "error": 0xEF4444,  # red
    "denied": 0xEF4444,
    # Alert framework severities (shared with email subject prefix).
    "warning": 0xF59E0B,
    "critical": 0xDC2626,  # darker red
}

_TEAMS_COLOURS = {
    "info": "4FACFE",
    "warn": "F59E0B",
    "error": "EF4444",
    "denied": "EF4444",
    "warning": "F59E0B",
    "critical": "DC2626",
}


def _payload_summary_lines(payload: dict[str, Any]) -> tuple[str, str]:
    """Return ``(short_title, longer_body)`` for chat-card rendering.

    Audit rows carry ``action`` + ``resource_type`` + ``resource_display``;
    alert events carry ``rule_name`` + ``subject_display`` + ``message``;
    digests (issue #90 Phase 2) carry ``title`` + ``summary``. Each
    flavor lands in the same chat / SMTP renderers so a single target
    can receive all three.
    """
    if payload.get("kind") == "alert":
        rule_name = payload.get("rule_name") or "alert"
        subject = payload.get("subject_display") or payload.get("subject_id", "")
        msg = payload.get("message") or ""
        title = f"[{payload.get('severity', 'warning').upper()}] {rule_name}"
        body = subject if not msg else f"{subject}\n{msg}" if subject else msg
        return title, body
    if payload.get("kind") == "digest":
        title = payload.get("title") or "Operator Daily Digest"
        body = payload.get("summary") or payload.get("message") or "(no summary)"
        return title, body
    action = payload.get("action") or "audit"
    rtype = payload.get("resource_type") or ""
    rid = payload.get("resource_display") or payload.get("resource_id", "")
    user = payload.get("user_display_name") or "system"
    result = payload.get("result") or "success"
    title = f"{action} · {rtype}".strip(" ·")
    body = f"{rid} ({result}) by {user}".strip()
    return title, body


def _slack_payload(payload: dict[str, Any]) -> dict[str, Any]:
    title, body = _payload_summary_lines(payload)
    sev = _payload_severity(payload)
    icon = {
        "info": ":information_source:",
        "warn": ":warning:",
        "warning": ":warning:",
        "error": ":rotating_light:",
        "denied": ":no_entry:",
        "critical": ":rotating_light:",
    }.get(sev, ":information_source:")
    return {
        "text": f"{icon} *{title}*\n{body}",
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"{icon} *{title}*"},
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": body or "—"}},
        ],
    }


def _teams_payload(payload: dict[str, Any]) -> dict[str, Any]:
    title, body = _payload_summary_lines(payload)
    sev = _payload_severity(payload)
    colour = _TEAMS_COLOURS.get(sev, "4FACFE")
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": colour,
        "title": title,
        "text": body or "—",
    }


def _discord_payload(payload: dict[str, Any]) -> dict[str, Any]:
    title, body = _payload_summary_lines(payload)
    sev = _payload_severity(payload)
    colour = _SEVERITY_COLOURS.get(sev, _SEVERITY_COLOURS["info"])
    return {
        "username": "SpatiumDDI",
        "embeds": [
            {
                "title": title[:256],
                "description": (body or "—")[:4096],
                "color": colour,
            }
        ],
    }


def _shape_webhook_body(flavor: str, payload: dict[str, Any]) -> dict[str, Any]:
    if flavor == "slack":
        return _slack_payload(payload)
    if flavor == "teams":
        return _teams_payload(payload)
    if flavor == "discord":
        return _discord_payload(payload)
    return payload


# ── SMTP transport ─────────────────────────────────────────────────────────


async def _send_smtp(
    host: str,
    port: int,
    security: str,
    username: str,
    password: str,
    from_address: str,
    to_addresses: list[str],
    subject: str,
    body: str,
    reply_to: str | None = None,
) -> None:
    """Send a single text email via stdlib ``smtplib`` in a thread.

    Async-friendly via ``asyncio.to_thread`` — alert volumes are low
    enough that a dedicated async SMTP client (``aiosmtplib``) doesn't
    earn its dep weight. ``security`` picks the connect mode:
    ``ssl`` = implicit TLS on connect (port 465 typical),
    ``starttls`` = upgrade plain socket to TLS after EHLO (port 587),
    ``none`` = no encryption (trusted-network relays only).
    """
    if not to_addresses:
        return

    import smtplib
    from email.message import EmailMessage

    def _sync_send() -> None:
        msg = EmailMessage()
        msg["From"] = from_address
        msg["To"] = ", ".join(to_addresses)
        msg["Subject"] = subject
        if reply_to:
            msg["Reply-To"] = reply_to
        msg.set_content(body)

        if security == "ssl":
            with smtplib.SMTP_SSL(host, port, timeout=10) as smtp:
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(msg)
            return

        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            if security == "starttls":
                smtp.starttls()
                smtp.ehlo()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(msg)

    await asyncio.to_thread(_sync_send)


def _smtp_subject_body(payload: dict[str, Any]) -> tuple[str, str]:
    """Render a plain-text subject + body for an audit or alert payload.

    Default templates are deliberately simple — Jinja overrides are a
    follow-up if operators ask for per-rule customisation. Subject is
    prefixed with the severity for inbox-side filtering / colouring.
    """
    title, summary = _payload_summary_lines(payload)
    sev = _payload_severity(payload)
    subject = f"[SpatiumDDI {sev.upper()}] {title}"

    if payload.get("kind") == "alert":
        body_lines = [
            f"Rule: {payload.get('rule_name', '?')} ({payload.get('rule_type', '?')})",
            f"Severity: {sev}",
            f"Subject: {payload.get('subject_display') or payload.get('subject_id', '')}",
            f"Fired at: {payload.get('fired_at', '')}",
            "",
            payload.get("message") or "(no message)",
        ]
    elif payload.get("kind") == "digest":
        body_lines = [
            f"Window: {payload.get('rollup', {}).get('window_start_utc', '?')}"
            f" → {payload.get('rollup', {}).get('window_end_utc', '?')} (UTC)",
            "",
            payload.get("summary") or payload.get("message") or "(no summary)",
        ]
    else:
        body_lines = [
            f"Action: {payload.get('action', '?')}",
            f"Resource: {payload.get('resource_type', '?')} — "
            f"{payload.get('resource_display') or payload.get('resource_id', '')}",
            f"User: {payload.get('user_display_name') or 'system'}",
            f"Result: {payload.get('result', 'success')}",
            f"Timestamp: {payload.get('timestamp', '')}",
        ]
        if summary:
            body_lines.extend(["", summary])
    return subject, "\n".join(body_lines)


# ── Per-target delivery ────────────────────────────────────────────────────


def _target_accepts(target: dict[str, Any], payload: dict[str, Any]) -> bool:
    """Filter gate: honour min_severity + resource_types on the target."""
    ms = target.get("min_severity")
    if ms:
        needed = _SEVERITY_RANK.get(ms.lower())
        # #1031: this read ``payload["result"]``, a key only AUDIT rows
        # carry, so every alert bucketed to ``info`` and any target with a
        # threshold above ``info`` dropped the lot — criticals included.
        got = _SEVERITY_RANK.get(_payload_severity(payload))
        # Unknown on either side is fail-OPEN, deliberately: a severity
        # string we cannot rank says nothing about whether the operator
        # wanted the event, and silently swallowing it is the failure
        # being fixed here.
        if needed is not None and got is not None and got < needed:
            return False
    rtypes = target.get("resource_types") or []
    if rtypes:
        # Alerts name their subject as ``subject_type``, drawn from the
        # same vocabulary as an audit row's ``resource_type``
        # (``appliance``, ``dns_zone``, …). Without this fallback a
        # target with an allowlist dropped every alert for want of a
        # key — the #1031 failure again, in a different field. Digests
        # set ``resource_type`` themselves and are unaffected.
        #
        # ONE rule NAMESPACES it: ``compliance_change`` fires against an
        # audit row and reports ``audit:<resource_type>``. Matching only
        # the raw string would leave exactly those alerts failing every
        # allowlist — the bug this fallback exists to fix, surviving in
        # the one rule whose subject IS an audited resource. Both forms
        # are accepted, so an operator scoping a target to ``dns_zone``
        # gets the compliance alerts about dns_zones too.
        candidates = [payload.get("resource_type"), payload.get("subject_type")]
        subject = payload.get("subject_type")
        if isinstance(subject, str) and ":" in subject:
            candidates.append(subject.split(":", 1)[1])
        if not any(c in rtypes for c in candidates if c):
            return False
    return True


async def _deliver_to_target(target: dict[str, Any], payload: dict[str, Any]) -> None:
    if not _target_accepts(target, payload):
        return
    kind = target.get("kind")
    try:
        if kind == "syslog":
            message = render_for_target(
                target.get("format", "rfc5424_json"),
                int(target.get("facility", 16)),
                payload,
            )
            await _send_syslog(
                target["host"],
                int(target["port"]),
                target.get("protocol", "udp"),
                message,
                ca_cert_pem=target.get("ca_cert_pem"),
            )
        elif kind == "webhook":
            flavor = (target.get("webhook_flavor") or "generic").lower()
            body = _shape_webhook_body(flavor, payload)
            # Slack / Teams / Discord incoming-webhook URLs accept
            # unauthenticated POSTs by design; forwarding the
            # ``Authorization`` header would just confuse them. Keep
            # auth_header for ``generic`` only.
            auth = target.get("auth_header") or "" if flavor == "generic" else ""
            await _send_webhook(target["url"], auth, body)
        elif kind == "smtp":
            password = target.get("smtp_password") or ""
            to_addrs = target.get("smtp_to_addresses") or []
            if not target.get("smtp_host") or not target.get("smtp_from_address") or not to_addrs:
                logger.warning(
                    "audit_forward_smtp_missing_config",
                    target=target.get("name"),
                )
                return
            subject, email_body = _smtp_subject_body(payload)
            await _send_smtp(
                target["smtp_host"],
                int(target.get("smtp_port", 587)),
                target.get("smtp_security", "starttls"),
                target.get("smtp_username", ""),
                password,
                target["smtp_from_address"],
                list(to_addrs),
                subject,
                email_body,
                reply_to=target.get("smtp_reply_to") or None,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "audit_forward_target_failed",
            target=target.get("name"),
            kind=kind,
            error=str(exc),
        )


# ── Legacy deliver helper (alerts.py still calls _deliver_one indirectly) ──


async def _deliver_one(
    payload: dict[str, Any],
    row_summary: dict[str, Any],  # noqa: ARG001 — retained for call compat
    syslog_cfg: dict[str, Any] | None,
    webhook_cfg: dict[str, Any] | None,
) -> None:
    """Legacy path — shape-compatible with pre-multi-target callers."""
    if syslog_cfg is not None:
        await _deliver_to_target(
            {
                "kind": "syslog",
                "format": "rfc5424_json",
                "host": syslog_cfg["host"],
                "port": syslog_cfg["port"],
                "protocol": syslog_cfg["protocol"],
                "facility": syslog_cfg["facility"],
            },
            payload,
        )
    if webhook_cfg is not None:
        await _deliver_to_target(
            {
                "kind": "webhook",
                "url": webhook_cfg["url"],
                "auth_header": webhook_cfg.get("auth_header", ""),
            },
            payload,
        )


# ── Config loading ─────────────────────────────────────────────────────────


@asynccontextmanager
async def _ephemeral_session() -> AsyncIterator[AsyncSession]:
    """Short-lived engine + session for audit-forward config reads.

    Why: the ``after_commit`` listener runs on whatever event loop
    committed the parent session. In FastAPI that's the long-lived
    request loop; in Celery workers each task spins its own loop via
    ``asyncio.run``. Using the global engine from ``app.db`` would
    reuse asyncpg connections created on a prior loop and race them
    ("another operation is in progress"). An ephemeral engine with
    ``NullPool`` has no loop-bound pool state to leak.
    """
    engine = create_async_engine(_app_settings.database_url, poolclass=NullPool)
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session
    finally:
        await engine.dispose()


async def _load_forward_config() -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Back-compat shim: return *one* syslog + *one* webhook config dict.

    Used by alerts.py. Prefers the first enabled row of each kind from
    ``audit_forward_target``; falls back to the flat settings columns
    when the table is empty.
    """
    async with _ephemeral_session() as session:
        res = await session.execute(
            select(AuditForwardTarget).where(AuditForwardTarget.enabled.is_(True))
        )
        rows = list(res.scalars().all())

    syslog_cfg: dict[str, Any] | None = None
    webhook_cfg: dict[str, Any] | None = None
    for t in rows:
        if syslog_cfg is None and t.kind == "syslog" and t.host:
            syslog_cfg = {
                "host": t.host,
                "port": int(t.port or 514),
                "protocol": t.protocol or "udp",
                "facility": int(t.facility or 16),
            }
        elif webhook_cfg is None and t.kind == "webhook" and t.url:
            webhook_cfg = {
                "url": t.url,
                "auth_header": t.auth_header or "",
            }
        if syslog_cfg is not None and webhook_cfg is not None:
            break

    if syslog_cfg is not None or webhook_cfg is not None:
        return syslog_cfg, webhook_cfg

    # No targets configured — fall back to legacy flat columns so a
    # pre-multi-target deployment keeps forwarding after upgrade without
    # the operator having to re-create the row.
    async with _ephemeral_session() as session:
        ps = await session.get(PlatformSettings, _SINGLETON_ID)
    if ps is None:
        return None, None
    if (
        ps.audit_forward_syslog_enabled
        and ps.audit_forward_syslog_host
        and ps.audit_forward_syslog_port
    ):
        syslog_cfg = {
            "host": ps.audit_forward_syslog_host,
            "port": int(ps.audit_forward_syslog_port),
            "protocol": ps.audit_forward_syslog_protocol or "udp",
            "facility": int(ps.audit_forward_syslog_facility),
        }
    if ps.audit_forward_webhook_enabled and ps.audit_forward_webhook_url:
        webhook_cfg = {
            "url": ps.audit_forward_webhook_url,
            "auth_header": ps.audit_forward_webhook_auth_header or "",
        }
    return syslog_cfg, webhook_cfg


async def _load_targets() -> list[dict[str, Any]]:
    """Return every enabled target as a dict. Includes a fallback from
    the legacy flat settings when the targets table is empty, so existing
    deployments keep forwarding across the upgrade boundary."""
    async with _ephemeral_session() as session:
        res = await session.execute(
            select(AuditForwardTarget).where(AuditForwardTarget.enabled.is_(True))
        )
        rows = list(res.scalars().all())

    out: list[dict[str, Any]] = []
    for t in rows:
        if t.kind == "syslog" and t.host:
            out.append(
                {
                    "name": t.name,
                    "kind": "syslog",
                    "format": t.format,
                    "host": t.host,
                    "port": int(t.port),
                    "protocol": t.protocol,
                    "facility": int(t.facility),
                    "ca_cert_pem": t.ca_cert_pem,
                    "min_severity": t.min_severity,
                    "resource_types": t.resource_types,
                }
            )
        elif t.kind == "webhook" and t.url:
            out.append(
                {
                    "name": t.name,
                    "kind": "webhook",
                    "webhook_flavor": t.webhook_flavor or "generic",
                    "url": t.url,
                    "auth_header": t.auth_header or "",
                    "min_severity": t.min_severity,
                    "resource_types": t.resource_types,
                }
            )
        elif t.kind == "smtp" and t.smtp_host and t.smtp_from_address:
            # Decrypt the password lazily here so the cleartext stays
            # off the in-memory target dict any longer than necessary —
            # ``_send_smtp`` is the only consumer.
            password = ""
            if t.smtp_password_encrypted:
                try:
                    from app.core.crypto import decrypt_str

                    password = decrypt_str(t.smtp_password_encrypted)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "audit_forward_smtp_decrypt_failed",
                        target=t.name,
                        error=str(exc),
                    )
                    continue
            out.append(
                {
                    "name": t.name,
                    "kind": "smtp",
                    "smtp_host": t.smtp_host,
                    "smtp_port": int(t.smtp_port),
                    "smtp_security": t.smtp_security,
                    "smtp_username": t.smtp_username,
                    "smtp_password": password,
                    "smtp_from_address": t.smtp_from_address,
                    "smtp_to_addresses": list(t.smtp_to_addresses or []),
                    "smtp_reply_to": t.smtp_reply_to or None,
                    "min_severity": t.min_severity,
                    "resource_types": t.resource_types,
                }
            )
    if out:
        return out

    # Legacy flat-config fallback.
    syslog_cfg, webhook_cfg = await _load_forward_config()
    if syslog_cfg is not None:
        out.append(
            {
                "name": "Legacy Syslog",
                "kind": "syslog",
                "format": "rfc5424_json",
                **syslog_cfg,
                "ca_cert_pem": None,
                "min_severity": None,
                "resource_types": None,
            }
        )
    if webhook_cfg is not None:
        out.append(
            {
                "name": "Legacy Webhook",
                "kind": "webhook",
                **webhook_cfg,
                "min_severity": None,
                "resource_types": None,
            }
        )
    return out


# ── Dispatch ───────────────────────────────────────────────────────────────


async def _dispatch(rows: list[dict[str, Any]]) -> None:
    targets = await _load_targets()
    if not targets:
        return

    tasks: list[Any] = []
    for r in rows:
        payload = r["payload"]
        for t in targets:
            tasks.append(_deliver_to_target(t, payload))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


# ── Listener wiring ────────────────────────────────────────────────────────


def _register_session_listener() -> None:
    """Install the ``after_flush`` + ``after_commit`` listeners.

    Runs once at import time — idempotent because SQLAlchemy's event
    system de-dups listener identity.
    """

    @event.listens_for(AsyncSession.sync_session_class, "after_flush")
    def _after_flush(session: Any, flush_context: Any) -> None:  # noqa: ARG001
        new_audits = [obj for obj in session.new if isinstance(obj, AuditLog)]
        if not new_audits:
            return
        snapshots = getattr(session, _PENDING_ATTR, None) or []
        for row in new_audits:
            snapshots.append(
                {
                    "payload": _serialize(row),
                    "result": row.result,
                    "timestamp": getattr(row, "timestamp", None) or datetime.now(UTC),
                }
            )
        setattr(session, _PENDING_ATTR, snapshots)

    @event.listens_for(AsyncSession.sync_session_class, "after_commit")
    def _after_commit(session: Any) -> None:
        snapshots = getattr(session, _PENDING_ATTR, None)
        if not snapshots:
            return
        setattr(session, _PENDING_ATTR, [])
        # #1168 — see ``event_publisher``: a Celery task's loop cancelled
        # this delivery as the task returned.
        dispatch("audit_forward", lambda: _dispatch(snapshots), count=len(snapshots))

    @event.listens_for(AsyncSession.sync_session_class, "after_rollback")
    def _after_rollback(session: Any) -> None:
        if getattr(session, _PENDING_ATTR, None):
            setattr(session, _PENDING_ATTR, [])


_register_session_listener()


__all__: list[str] = [
    "render_for_target",
    "_send_syslog",
    "_send_webhook",
    "_deliver_to_target",
    "_load_targets",
]
