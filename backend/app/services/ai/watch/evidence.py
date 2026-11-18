"""Evidence for Copilot Watch (issue #4405).

The design rule: the deterministic detectors detect; the model
correlates, explains and prioritises. This module is the detectors' side
of that line. It reads what they have already recorded and nothing else:

* open alert events (``alert:<id>``),
* failing checks in the current pass of each enabled conformity policy
  (``conformity:<result id>``),
* DNS / DHCP servers the health checks mark unreachable or in error
  (``server:<kind>:<id>``),
* agents that could not apply their configuration (``agent:<kind>:<id>``),
* recent audit rows that touch the subjects above (``audit:<id>``).

:func:`build_evidence_pack` is what a run sends to the model.
:func:`verify_refs` is what decides whether a finding the model returned
rests on anything: a reference counts only if the row exists and, for
the four detector types, is still reporting a problem. :func:`refresh`
re-reads stored evidence later, which is how a finding closes when its
evidence clears.

Every section is read as the Watch identity: a section the identity has
no ``read`` grant for is left out of the pack and its references do not
verify, so narrowing the identity's roles narrows what reaches the model.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import user_has_permission
from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.conformity import ConformityPolicy, ConformityResult
from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer
from app.services import feature_modules as fm_svc
from app.services.agents.config_apply import FAILED_STATUSES

TYPE_ALERT = "alert"
TYPE_CONFORMITY = "conformity"
TYPE_SERVER = "server"
TYPE_AGENT = "agent"
TYPE_AUDIT = "audit"
# The types a detector produced. An audit row is context, not a detection:
# it never clears, and it never keeps a finding open by itself for long.
DETECTOR_TYPES: frozenset[str] = frozenset({TYPE_ALERT, TYPE_CONFORMITY, TYPE_SERVER, TYPE_AGENT})

# Server ``status`` values the health checks set when a server is not well.
UNHEALTHY_SERVER_STATUSES: tuple[str, ...] = ("unreachable", "error")

# Caps per section. The pack has to fit a small local model's context,
# and a count of what was left out is sent alongside.
MAX_ALERTS = 60
MAX_CONFORMITY = 40
MAX_SERVERS = 40
MAX_AGENTS = 40
MAX_AUDIT = 25
AUDIT_WINDOW = timedelta(hours=24)
_TEXT_CAP = 400

_SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}
_SERVER_MODELS: dict[str, tuple[Any, tuple[str, str]]] = {
    "dns_server": (DNSServer, ("read", "dns_group")),
    "dhcp_server": (DHCPServer, ("read", "dhcp_server")),
}


@dataclass(frozen=True)
class EvidenceItem:
    """One piece of evidence, as stored on a finding and sent to the model."""

    ref: str
    type: str
    # ``<kind>:<id>`` of the thing the evidence is about. Two pieces of
    # evidence about one server share a subject, whatever reported them.
    subject: str
    display: str
    severity: str = ""
    detail: str = ""
    at: str | None = None
    # What :func:`refresh` needs to tell whether it still holds.
    key: dict[str, str] = field(default_factory=dict)

    def for_model(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ref": self.ref, "subject": self.subject, "what": self.display}
        if self.severity:
            out["severity"] = self.severity
        if self.detail:
            out["detail"] = self.detail
        if self.at:
            out["at"] = self.at
        return out

    def stored(self, *, cleared: bool = False) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "type": self.type,
            "subject": self.subject,
            "display": self.display,
            "severity": self.severity,
            "detail": self.detail,
            "at": self.at,
            "key": self.key,
            "cleared": cleared,
        }


@dataclass
class EvidencePack:
    items: list[EvidenceItem] = field(default_factory=list)
    # ``{section: how many rows were left out by the cap}``.
    truncated: dict[str, int] = field(default_factory=dict)
    # Sections the Watch identity may not read, or whose module is off.
    omitted: list[str] = field(default_factory=list)

    @property
    def detector_items(self) -> list[EvidenceItem]:
        return [i for i in self.items if i.type in DETECTOR_TYPES]

    def for_model(self) -> dict[str, Any]:
        sections: dict[str, list[dict[str, Any]]] = {}
        names = {
            TYPE_ALERT: "open_alerts",
            TYPE_CONFORMITY: "failing_conformity_checks",
            TYPE_SERVER: "unhealthy_servers",
            TYPE_AGENT: "agents_that_rejected_their_config",
            TYPE_AUDIT: "recent_changes_to_these_subjects",
        }
        for item in self.items:
            sections.setdefault(names[item.type], []).append(item.for_model())
        out: dict[str, Any] = dict(sections)
        if self.truncated:
            out["not_shown"] = self.truncated
        if self.omitted:
            out["sections_not_available"] = self.omitted
        return out


def _clip(text: str | None) -> str:
    text = (text or "").strip()
    return text if len(text) <= _TEXT_CAP else text[: _TEXT_CAP - 1] + "…"


def _iso(ts: datetime | None) -> str | None:
    return ts.astimezone(UTC).isoformat(timespec="seconds") if ts else None


def _may(user: User, section: str) -> bool:
    if section == TYPE_ALERT:
        return user_has_permission(user, "read", "alert")
    if section == TYPE_CONFORMITY:
        return user_has_permission(user, "read", "conformity")
    if section == TYPE_AUDIT:
        return user_has_permission(user, "read", "audit_log")
    return True


def _may_kind(user: User, kind: str) -> bool:
    spec = _SERVER_MODELS.get(kind)
    return spec is not None and user_has_permission(user, *spec[1])


# ── Item builders ─────────────────────────────────────────────────────


def _alert_item(ev: AlertEvent, rule: AlertRule | None) -> EvidenceItem:
    rule_label = f"{rule.name} ({rule.rule_type})" if rule is not None else "alert"
    return EvidenceItem(
        ref=f"{TYPE_ALERT}:{ev.id}",
        type=TYPE_ALERT,
        subject=f"{ev.subject_type}:{ev.subject_id}",
        display=_clip(f"{rule_label}: {ev.subject_display or ev.subject_id}"),
        severity=ev.severity,
        detail=_clip(ev.message),
        at=_iso(ev.fired_at),
        key={
            "rule_id": str(ev.rule_id),
            "subject_type": ev.subject_type,
            "subject_id": ev.subject_id,
        },
    )


def _conformity_item(res: ConformityResult, policy: ConformityPolicy) -> EvidenceItem:
    return EvidenceItem(
        ref=f"{TYPE_CONFORMITY}:{res.id}",
        type=TYPE_CONFORMITY,
        subject=f"{res.resource_kind}:{res.resource_id}",
        display=_clip(
            f"{policy.name} ({policy.framework}) fails on "
            f"{res.resource_display or res.resource_id}"
        ),
        severity=policy.severity,
        detail=_clip(res.detail),
        at=_iso(res.evaluated_at),
        key={
            "policy_id": str(res.policy_id),
            "resource_kind": res.resource_kind,
            "resource_id": res.resource_id,
        },
    )


def _server_item(kind: str, row: Any) -> EvidenceItem:
    return EvidenceItem(
        ref=f"{TYPE_SERVER}:{kind}:{row.id}",
        type=TYPE_SERVER,
        subject=f"{kind}:{row.id}",
        display=_clip(f"{kind.replace('_', ' ')} {row.name} is {row.status}"),
        severity="critical",
        detail="",
        at=_iso(getattr(row, "last_health_check_at", None)),
        key={"kind": kind, "id": str(row.id)},
    )


def _agent_item(kind: str, row: Any) -> EvidenceItem:
    return EvidenceItem(
        ref=f"{TYPE_AGENT}:{kind}:{row.id}",
        type=TYPE_AGENT,
        subject=f"{kind}:{row.id}",
        display=_clip(
            f"{kind.replace('_', ' ')} {row.name} could not apply its configuration "
            f"({row.config_apply_status})"
        ),
        severity="warning" if row.config_apply_status == "reverted" else "critical",
        detail=_clip(row.config_apply_error),
        at=_iso(row.config_apply_at),
        key={"kind": kind, "id": str(row.id)},
    )


def _audit_item(row: AuditLog) -> EvidenceItem:
    return EvidenceItem(
        ref=f"{TYPE_AUDIT}:{row.id}",
        type=TYPE_AUDIT,
        subject=f"{row.resource_type}:{row.resource_id}",
        display=_clip(
            f"{row.user_display_name} {row.action} {row.resource_type} "
            f"{row.resource_display}"
        ),
        detail=_clip(", ".join(row.changed_fields or [])),
        at=_iso(row.timestamp),
    )


# ── Current detector state ────────────────────────────────────────────


async def _open_alerts(db: AsyncSession) -> list[tuple[AlertEvent, AlertRule]]:
    stmt = (
        select(AlertEvent, AlertRule)
        .join(AlertRule, AlertRule.id == AlertEvent.rule_id)
        .where(AlertEvent.resolved_at.is_(None))
        .order_by(desc(AlertEvent.fired_at))
    )
    return [(ev, rule) for ev, rule in (await db.execute(stmt)).all()]


async def _current_conformity_failures(
    db: AsyncSession,
) -> list[tuple[ConformityResult, ConformityPolicy]]:
    stmt = (
        select(ConformityResult, ConformityPolicy)
        .join(
            ConformityPolicy,
            and_(
                ConformityPolicy.id == ConformityResult.policy_id,
                ConformityResult.evaluated_at == ConformityPolicy.last_evaluated_at,
            ),
        )
        .where(ConformityPolicy.enabled.is_(True))
        .where(ConformityResult.status == "fail")
        .order_by(desc(ConformityResult.evaluated_at), ConformityResult.id)
    )
    return [(res, pol) for res, pol in (await db.execute(stmt)).all()]


async def build_evidence_pack(db: AsyncSession, principal: User) -> EvidencePack:
    """Everything the detectors currently report, as the Watch identity
    may read it. Deterministic: no model is involved, and a healthy
    install produces a pack with no detector items."""
    pack = EvidencePack()
    subjects: set[tuple[str, str]] = set()

    if _may(principal, TYPE_ALERT):
        rows = await _open_alerts(db)
        rows.sort(key=lambda r: (_SEVERITY_RANK.get(r[0].severity, 3), -r[0].fired_at.timestamp()))
        for ev, rule in rows[:MAX_ALERTS]:
            pack.items.append(_alert_item(ev, rule))
            subjects.add((ev.subject_type, ev.subject_id))
        if len(rows) > MAX_ALERTS:
            pack.truncated["open_alerts"] = len(rows) - MAX_ALERTS
    else:
        pack.omitted.append("open_alerts")

    if await fm_svc.is_module_enabled(db, "compliance.conformity") and _may(
        principal, TYPE_CONFORMITY
    ):
        failures = await _current_conformity_failures(db)
        for res, pol in failures[:MAX_CONFORMITY]:
            pack.items.append(_conformity_item(res, pol))
            subjects.add((res.resource_kind, res.resource_id))
        if len(failures) > MAX_CONFORMITY:
            pack.truncated["failing_conformity_checks"] = len(failures) - MAX_CONFORMITY
    else:
        pack.omitted.append("failing_conformity_checks")

    servers: list[EvidenceItem] = []
    agents: list[EvidenceItem] = []
    for kind, (model, _perm) in _SERVER_MODELS.items():
        if not _may_kind(principal, kind):
            pack.omitted.append(f"{kind}_health")
            continue
        unhealthy = (
            (
                await db.execute(
                    select(model)
                    .where(model.status.in_(UNHEALTHY_SERVER_STATUSES))
                    .order_by(model.name)
                )
            )
            .scalars()
            .all()
        )
        servers.extend(_server_item(kind, r) for r in unhealthy)
        failed = (
            (
                await db.execute(
                    select(model)
                    .where(model.config_apply_status.in_(sorted(FAILED_STATUSES)))
                    .order_by(model.name)
                )
            )
            .scalars()
            .all()
        )
        agents.extend(_agent_item(kind, r) for r in failed)
    for label, found, cap in (
        ("unhealthy_servers", servers, MAX_SERVERS),
        ("agents_that_rejected_their_config", agents, MAX_AGENTS),
    ):
        pack.items.extend(found[:cap])
        if len(found) > cap:
            pack.truncated[label] = len(found) - cap
        for item in found[:cap]:
            kind, _, rid = item.subject.partition(":")
            subjects.add((kind, rid))

    # What changed on those subjects in the last day. Alert subjects name
    # servers as ``server``; the audit log names them by their real type,
    # so the match is on the id alone.
    subject_ids = sorted({rid for _kind, rid in subjects})
    if subject_ids and _may(principal, TYPE_AUDIT):
        since = datetime.now(UTC) - AUDIT_WINDOW
        audit_rows = (
            (
                await db.execute(
                    select(AuditLog)
                    .where(AuditLog.timestamp >= since)
                    .where(AuditLog.resource_id.in_(subject_ids))
                    .where(AuditLog.action.in_(("create", "update", "delete")))
                    .where(AuditLog.result == "success")
                    .order_by(desc(AuditLog.timestamp))
                    .limit(MAX_AUDIT)
                )
            )
            .scalars()
            .all()
        )
        pack.items.extend(_audit_item(r) for r in audit_rows)
    elif subject_ids:
        pack.omitted.append("recent_changes_to_these_subjects")

    return pack


# ── Reference checks ──────────────────────────────────────────────────


def _as_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return None


async def _resolve_ref(db: AsyncSession, principal: User, ref: str) -> EvidenceItem | None:
    """The live evidence ``ref`` names, or None.

    None covers every way a reference can be worthless: malformed, no
    such row, the row no longer reports a problem (a resolved alert, a
    check that now passes, a server that is healthy again), or a type
    the Watch identity may not read.
    """
    type_, _, rest = ref.strip().partition(":")
    if not rest:
        return None

    if type_ == TYPE_ALERT:
        rid = _as_uuid(rest)
        if rid is None or not _may(principal, TYPE_ALERT):
            return None
        ev = await db.get(AlertEvent, rid)
        if ev is None or ev.resolved_at is not None:
            return None
        return _alert_item(ev, await db.get(AlertRule, ev.rule_id))

    if type_ == TYPE_CONFORMITY:
        rid = _as_uuid(rest)
        if rid is None or not _may(principal, TYPE_CONFORMITY):
            return None
        if not await fm_svc.is_module_enabled(db, "compliance.conformity"):
            return None
        res = await db.get(ConformityResult, rid)
        if res is None or res.status != "fail":
            return None
        pol = await db.get(ConformityPolicy, res.policy_id)
        if pol is None or not pol.enabled or pol.last_evaluated_at != res.evaluated_at:
            return None
        return _conformity_item(res, pol)

    if type_ in (TYPE_SERVER, TYPE_AGENT):
        kind, _, raw_id = rest.partition(":")
        rid = _as_uuid(raw_id)
        if rid is None or not _may_kind(principal, kind):
            return None
        row = await db.get(_SERVER_MODELS[kind][0], rid)
        if row is None:
            return None
        if type_ == TYPE_SERVER:
            return _server_item(kind, row) if row.status in UNHEALTHY_SERVER_STATUSES else None
        return _agent_item(kind, row) if row.config_apply_status in FAILED_STATUSES else None

    if type_ == TYPE_AUDIT:
        rid = _as_uuid(rest)
        if rid is None or not _may(principal, TYPE_AUDIT):
            return None
        audit = await db.get(AuditLog, rid)
        return _audit_item(audit) if audit is not None else None

    return None


async def verify_refs(
    db: AsyncSession, principal: User, refs: list[str]
) -> tuple[list[EvidenceItem], list[str]]:
    """Split ``refs`` into the evidence that exists and the refs that do
    not. Order is kept and duplicates are dropped."""
    seen: set[str] = set()
    good: list[EvidenceItem] = []
    bad: list[str] = []
    for ref in refs:
        if not isinstance(ref, str) or ref in seen:
            continue
        seen.add(ref)
        item = await _resolve_ref(db, principal, ref)
        if item is None:
            bad.append(ref)
        else:
            good.append(item)
    return good, bad


async def refresh(db: AsyncSession, stored: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Re-read a finding's stored evidence and mark what has cleared.

    This is the closing check, so it is not narrowed by the Watch
    identity's roles: a finding filed while the identity could read alerts
    must still close when the alert resolves, whatever the identity can
    read now. It reads only whether the stored rows still report a
    problem.

    An alert that resolved and fired again is the same problem under a
    new event id: the entry is moved to the open event for the same rule
    and subject instead of being marked cleared.
    """
    out: list[dict[str, Any]] = []
    for entry in stored:
        entry = dict(entry)
        type_ = entry.get("type")
        key = entry.get("key") or {}
        ref = str(entry.get("ref", ""))
        active = True
        if type_ == TYPE_ALERT:
            rid = _as_uuid(ref.partition(":")[2])
            ev = await db.get(AlertEvent, rid) if rid else None
            if ev is None or ev.resolved_at is not None:
                rule_id = _as_uuid(key.get("rule_id", ""))
                successor = None
                if rule_id is not None:
                    successor = await db.scalar(
                        select(AlertEvent)
                        .where(AlertEvent.rule_id == rule_id)
                        .where(AlertEvent.subject_type == key.get("subject_type"))
                        .where(AlertEvent.subject_id == key.get("subject_id"))
                        .where(AlertEvent.resolved_at.is_(None))
                    )
                if successor is None:
                    active = False
                else:
                    entry["ref"] = f"{TYPE_ALERT}:{successor.id}"
                    entry["at"] = _iso(successor.fired_at)
        elif type_ == TYPE_CONFORMITY:
            policy_id = _as_uuid(key.get("policy_id", ""))
            current = None
            if policy_id is not None:
                current = await db.scalar(
                    select(ConformityResult)
                    .join(
                        ConformityPolicy,
                        and_(
                            ConformityPolicy.id == ConformityResult.policy_id,
                            ConformityResult.evaluated_at == ConformityPolicy.last_evaluated_at,
                        ),
                    )
                    .where(ConformityPolicy.enabled.is_(True))
                    .where(ConformityResult.policy_id == policy_id)
                    .where(ConformityResult.resource_kind == key.get("resource_kind"))
                    .where(ConformityResult.resource_id == key.get("resource_id"))
                    .where(ConformityResult.status == "fail")
                    .limit(1)
                )
            if current is None:
                active = False
            else:
                entry["ref"] = f"{TYPE_CONFORMITY}:{current.id}"
        elif type_ in (TYPE_SERVER, TYPE_AGENT):
            spec = _SERVER_MODELS.get(key.get("kind", ""))
            rid = _as_uuid(key.get("id", ""))
            row = await db.get(spec[0], rid) if spec and rid else None
            if row is None:
                active = False
            elif type_ == TYPE_SERVER:
                active = row.status in UNHEALTHY_SERVER_STATUSES
            else:
                active = row.config_apply_status in FAILED_STATUSES
        # TYPE_AUDIT: a record of something that happened; it never clears.
        entry["cleared"] = not active
        out.append(entry)
    return out


async def open_alert_severities(db: AsyncSession) -> dict[str, str]:
    """``{alert_event_id: severity}`` for every open alert: what the
    event trigger compares between ticks."""
    rows = await db.execute(
        select(AlertEvent.id, AlertEvent.severity).where(AlertEvent.resolved_at.is_(None))
    )
    return {str(eid): sev for eid, sev in rows.all()}


def severity_rank(severity: str) -> int:
    """Lower is worse; an unknown severity ranks last."""
    return _SEVERITY_RANK.get(severity, 3)


__all__ = [
    "DETECTOR_TYPES",
    "EvidenceItem",
    "EvidencePack",
    "TYPE_AUDIT",
    "build_evidence_pack",
    "open_alert_severities",
    "refresh",
    "severity_rank",
    "verify_refs",
]
