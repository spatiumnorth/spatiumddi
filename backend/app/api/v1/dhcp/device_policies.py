"""Fingerprint-driven device policy CRUD + preview (issue #700).

Wires device profiling to Kea client classes: the operator picks
fingerbank device classes and an outcome, and ``services.dhcp.device_policy``
compiles it into a match expression over the signatures that produced
those classifications.

Two endpoints exist purely so this is not a black box, which the issue
asks for explicitly:

* ``GET …/device-policies/{id}/preview`` returns the compiled
  expression, every signature that went into it, the ones excluded for
  ambiguity, and the MACs that currently match — i.e. which existing
  leases land in this class, before anything is applied.
* ``GET …/server-groups/{gid}/device-observations`` lists the device
  classes fingerbank has actually returned on this install, with counts,
  so the class picker offers what exists rather than a free-text box that
  silently matches nothing.

Permissions ride on ``dhcp_client_class``: a device policy *is* a client
class, generated rather than hand-written. Reads follow that resource
permission, so the builtin DHCP Editor role gains them with no role
migration.

**Writes are superadmin**, matching the hand-authored client-class
surface next door rather than quietly widening it — the two produce the
same Kea object, and a policy that can move devices into a quarantine
pool is not a smaller privilege than typing that class by hand.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp.scopes import validate_dhcp_options
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPServerGroup
from app.models.dhcp_device_policy import DHCPDevicePolicy
from app.models.dhcp_fingerprint import DHCPFingerprint
from app.services.dhcp.device_policy import (
    MAX_SIGNATURE_TERMS,
    compile_device_policy,
    slugify_class_name,
)
from app.services.dhcp.option_validation import normalize_options

router = APIRouter(
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_client_class"))],
)

# A manual override is interpolated verbatim into the Kea config, so an
# unbounded string is both a config-size problem and an easy way to make
# the whole group's config unparseable. See ``_validate_override``.
MAX_OVERRIDE_LENGTH = 8192

# Matched MACs returned by the preview. The full count is always reported
# separately, so this bounds the response without hiding the scale.
PREVIEW_MAC_LIMIT = 500


def _validate_override(expr: str | None) -> str | None:
    """Structurally check an operator-supplied match expression.

    This is deliberately *not* a Kea expression parser — operators need
    the real language for the override to be a usable escape hatch, and
    re-implementing Kea's grammar here would reject valid expressions
    while still missing invalid ones.

    What it does catch is the class of typo that takes the whole group
    down rather than just this policy: Kea rejects a malformed config
    *whole*, so an unbalanced parenthesis here stops every other class,
    scope and reservation in the group converging. That blast radius is
    the same one #876 and #899 documented for named.conf, and it is why
    an obviously-broken expression is refused at the API instead of at
    the agent.

    The agent still runs Kea's own ``config-test`` before applying, and
    #882's quarantine means a bundle Kea rejects is reverted rather than
    re-applied in a loop — so this is the first gate, not the only one.
    """
    if expr is None:
        return None
    expr = expr.strip()
    if not expr:
        return None
    if len(expr) > MAX_OVERRIDE_LENGTH:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Match expression is {len(expr)} characters; the limit is "
                f"{MAX_OVERRIDE_LENGTH}."
            ),
        )
    if expr.count("(") != expr.count(")"):
        raise HTTPException(
            status_code=422,
            detail=(
                "Unbalanced parentheses in the match expression. Kea rejects a "
                "malformed configuration in full, so this would stop every scope "
                "and class in this group from converging, not just this policy."
            ),
        )
    if expr.count("'") % 2:
        raise HTTPException(
            status_code=422,
            detail=(
                "Unbalanced quote in the match expression. Kea rejects a "
                "malformed configuration in full, so this would stop every scope "
                "and class in this group from converging, not just this policy."
            ),
        )
    return expr


# ── Schemas ─────────────────────────────────────────────────────────────────


class DevicePolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    enabled: bool = True
    device_classes: list[str] = Field(
        default_factory=list,
        description=(
            "Fingerbank device classes to match. These are fingerbank's own "
            "taxonomy strings, which sit at mixed granularity and are rarely "
            "the tidy category you would guess — real values include "
            '"HP Print Server", "Generic IoT", "Generic Android" and '
            '"Operating System". Always pick from GET '
            "/dhcp/server-groups/{id}/device-observations rather than typing "
            "one: a class string that does not appear there matches nothing."
        ),
    )
    options: dict[str, Any] = Field(default_factory=dict)
    lease_time: int | None = Field(
        default=None,
        ge=60,
        le=4294967295,
        description=(
            "Kea valid-lifetime for matched devices, in seconds. A short lease "
            "is what makes a quarantine reversible."
        ),
    )
    match_override: str | None = None
    include_ambiguous: bool = False
    priority: int = 100

    @field_validator("device_classes")
    @classmethod
    def _clean_classes(cls, v: list[str]) -> list[str]:
        # Deduplicate while preserving order, and drop blanks. A blank
        # entry would silently match every unclassified fingerprint.
        seen: set[str] = set()
        out: list[str] = []
        for item in v:
            item = (item or "").strip()
            if item and item not in seen:
                seen.add(item)
                out.append(item)
        return out


class DevicePolicyUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    enabled: bool | None = None
    device_classes: list[str] | None = None
    options: dict[str, Any] | None = None
    lease_time: int | None = Field(None, ge=60, le=4294967295)
    match_override: str | None = None
    include_ambiguous: bool | None = None
    priority: int | None = None


class DevicePolicyResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    name: str
    description: str
    enabled: bool
    class_name: str
    device_classes: list[str]
    options: dict[str, Any]
    lease_time: int | None
    match_override: str | None
    include_ambiguous: bool
    priority: int
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class SignatureOut(BaseModel):
    option_55: str | None
    option_60: str | None


class DevicePolicyPreviewOut(BaseModel):
    policy_id: uuid.UUID
    class_name: str
    # The expression that will be rendered — the operator's override when
    # one is set, otherwise the compiled one.
    expression: str
    source: str = Field(description="compiled | override | empty")
    # Always what the compiler produced, so an override can be compared
    # against it. Equal to ``expression`` when no override is set.
    compiled_expression: str
    signature_count: int
    confidence: int | None
    signatures: list[SignatureOut]
    ambiguous_signatures: list[SignatureOut]
    ambiguous_excluded: bool
    truncated: int
    max_signature_terms: int
    matched_macs: list[str]
    matched_macs_truncated: bool
    matched_device_count: int
    unclassified_matches: int
    warnings: list[str]
    renders: bool = Field(
        description=(
            "Whether this policy contributes a class to the next config bundle. "
            "False when it is disabled or compiles to nothing."
        )
    )


class DeviceObservationOut(BaseModel):
    device_class: str
    device_count: int
    signature_count: int
    # Fingerbank's own 0-100 confidence, surfaced because the class name
    # alone hides the difference between an identified device and a
    # vendor-only fallback. "Hardware Manufacturer" at 29 is fingerbank
    # saying it could not identify the device, which makes it a poor
    # policy target however plausible the name looks in a list.
    best_score: int | None
    avg_score: int | None


class DeviceObservationsOut(BaseModel):
    classes: list[DeviceObservationOut]
    unclassified_devices: int
    total_devices: int
    note: str


# ── Helpers ─────────────────────────────────────────────────────────────────


async def _get_group(db: DB, group_id: uuid.UUID) -> DHCPServerGroup:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")
    return grp


async def _get_policy(db: DB, policy_id: uuid.UUID) -> DHCPDevicePolicy:
    row = await db.get(DHCPDevicePolicy, policy_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Device policy not found")
    return row


async def _unique_class_name(db: DB, group_id: uuid.UUID, name: str) -> str:
    """Pick a group-unique Kea class name derived from the policy name.

    Collisions are resolved with a numeric suffix rather than by failing:
    two policies called "Printers" and "printers" slugify identically, and
    refusing the second would be a confusing way to say "pick a different
    name" for something the operator never sees.
    """
    base = slugify_class_name(name)
    candidate = base
    n = 2
    while True:
        exists = await db.execute(
            select(DHCPDevicePolicy.id).where(
                DHCPDevicePolicy.group_id == group_id,
                DHCPDevicePolicy.class_name == candidate,
            )
        )
        if exists.scalar_one_or_none() is None:
            return candidate
        candidate = f"{base}-{n}"
        n += 1


def _to_preview(policy: DHCPDevicePolicy, compiled: Any) -> DevicePolicyPreviewOut:
    return DevicePolicyPreviewOut(
        policy_id=policy.id,
        class_name=policy.class_name,
        expression=compiled.expression,
        source=compiled.source,
        compiled_expression=compiled.compiled_expression,
        signature_count=len(compiled.signatures),
        confidence=compiled.confidence,
        signatures=[
            SignatureOut(option_55=s.option_55, option_60=s.option_60) for s in compiled.signatures
        ],
        ambiguous_signatures=[
            SignatureOut(option_55=s.option_55, option_60=s.option_60) for s in compiled.ambiguous
        ],
        ambiguous_excluded=bool(compiled.ambiguous) and not policy.include_ambiguous,
        truncated=compiled.truncated,
        max_signature_terms=MAX_SIGNATURE_TERMS,
        # Capped for transport; the count is the whole population, so a
        # large estate reports honestly instead of returning a 50k-element
        # array to a modal that renders chips.
        matched_macs=compiled.matched_macs[:PREVIEW_MAC_LIMIT],
        matched_macs_truncated=len(compiled.matched_macs) > PREVIEW_MAC_LIMIT,
        matched_device_count=len(compiled.matched_macs),
        unclassified_matches=compiled.unclassified_matches,
        warnings=compiled.warnings,
        renders=bool(policy.enabled and compiled.expression),
    )


# ── Routes ──────────────────────────────────────────────────────────────────


@router.get(
    "/server-groups/{group_id}/device-policies",
    response_model=list[DevicePolicyResponse],
)
async def list_device_policies(
    group_id: uuid.UUID, db: DB, _: CurrentUser
) -> list[DHCPDevicePolicy]:
    res = await db.execute(
        select(DHCPDevicePolicy)
        .where(DHCPDevicePolicy.group_id == group_id)
        .order_by(DHCPDevicePolicy.priority, DHCPDevicePolicy.name)
    )
    return list(res.scalars().all())


@router.post(
    "/server-groups/{group_id}/device-policies",
    response_model=DevicePolicyResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_device_policy(
    group_id: uuid.UUID, body: DevicePolicyCreate, db: DB, user: SuperAdmin
) -> DHCPDevicePolicy:
    await _get_group(db, group_id)
    dupe = await db.execute(
        select(DHCPDevicePolicy.id).where(
            DHCPDevicePolicy.group_id == group_id,
            DHCPDevicePolicy.name == body.name,
        )
    )
    if dupe.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A device policy with that name exists")
    # Device policies are DHCPv4 only by construction (options 55 / 60).
    body.options = normalize_options(body.options)
    validate_dhcp_options(body.options, address_family="ipv4")
    override = _validate_override(body.match_override)

    payload = body.model_dump()
    payload["match_override"] = override
    row = DHCPDevicePolicy(
        group_id=group_id,
        class_name=await _unique_class_name(db, group_id, body.name),
        created_by_user_id=user.id,
        **payload,
    )
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_device_policy",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=body.model_dump(mode="json"),
    )
    collect_wake(dhcp_group_channel(group_id))
    await db.commit()
    await db.refresh(row)
    return row


@router.get("/device-policies/{policy_id}", response_model=DevicePolicyResponse)
async def get_device_policy(policy_id: uuid.UUID, db: DB, _: CurrentUser) -> DHCPDevicePolicy:
    return await _get_policy(db, policy_id)


@router.put("/device-policies/{policy_id}", response_model=DevicePolicyResponse)
async def update_device_policy(
    policy_id: uuid.UUID, body: DevicePolicyUpdate, db: DB, user: SuperAdmin
) -> DHCPDevicePolicy:
    row = await _get_policy(db, policy_id)
    changes = body.model_dump(exclude_unset=True)

    # ``exclude_unset`` is deliberate — it is what lets an explicit null
    # CLEAR a nullable field (``lease_time``, ``match_override``), which
    # ``exclude_none`` would make impossible. But it also lets a null
    # through to columns that are NOT NULL, where the blanket setattr below
    # turns it into an unhandled 500 on commit. So nulls are rejected for
    # exactly the non-nullable set, by name, rather than for everything.
    non_nullable = {
        "name",
        "description",
        "enabled",
        "device_classes",
        "options",
        "include_ambiguous",
        "priority",
    }
    nulled = sorted(k for k in changes if k in non_nullable and changes[k] is None)
    if nulled:
        raise HTTPException(
            status_code=422,
            detail=(
                f"{', '.join(nulled)} cannot be null. Omit the field to leave it "
                "unchanged, or send a value."
            ),
        )

    if "options" in changes:
        changes["options"] = normalize_options(changes["options"])
        validate_dhcp_options(changes["options"], address_family="ipv4", previous=row.options or {})
    if "match_override" in changes:
        changes["match_override"] = _validate_override(changes["match_override"])
    if "device_classes" in changes:
        seen: set[str] = set()
        cleaned: list[str] = []
        for item in changes["device_classes"] or []:
            item = (item or "").strip()
            if item and item not in seen:
                seen.add(item)
                cleaned.append(item)
        changes["device_classes"] = cleaned
    if "name" in changes and changes["name"] != row.name:
        dupe = await db.execute(
            select(DHCPDevicePolicy.id).where(
                DHCPDevicePolicy.group_id == row.group_id,
                DHCPDevicePolicy.name == changes["name"],
                DHCPDevicePolicy.id != row.id,
            )
        )
        if dupe.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="A device policy with that name exists")
    # ``class_name`` is deliberately NOT recomputed on rename. Pools bind to
    # a class by name, so regenerating it here would leave every pool with
    # a ``client-class`` naming a class that no longer exists — which Kea
    # accepts and which silently stops the pool serving anyone.
    for k, v in changes.items():
        setattr(row, k, v)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_device_policy",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    collect_wake(dhcp_group_channel(row.group_id))
    await db.commit()
    await db.refresh(row)
    return row


@router.delete("/device-policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device_policy(policy_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    row = await _get_policy(db, policy_id)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_device_policy",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    collect_wake(dhcp_group_channel(row.group_id))
    await db.delete(row)
    await db.commit()


@router.get("/device-policies/{policy_id}/preview", response_model=DevicePolicyPreviewOut)
async def preview_device_policy(
    policy_id: uuid.UUID, db: DB, _: CurrentUser
) -> DevicePolicyPreviewOut:
    """Show exactly what this policy compiles to, and who it catches.

    Genuinely read-only. An earlier cut stamped ``last_compiled_at`` here,
    which made a GET authorised by ``read`` perform an unaudited write that
    maintenance mode does not gate (it only holds POST/PUT/PATCH/DELETE).
    The column was dropped rather than moved: the only other place a
    compile happens is the config-bundle build, and stamping there would
    add a write to every agent long-poll tick. Compilation is stateless and
    always current, so there was nothing worth recording.
    """
    row = await _get_policy(db, policy_id)
    compiled = await compile_device_policy(db, row)
    return _to_preview(row, compiled)


@router.get(
    "/server-groups/{group_id}/device-observations",
    response_model=DeviceObservationsOut,
)
async def list_device_observations(
    group_id: uuid.UUID, db: DB, _: CurrentUser
) -> DeviceObservationsOut:
    """Fingerbank device classes actually observed, with device counts.

    Feeds the class picker. Offering a free-text box instead would let an
    operator build a policy against a class string that never appears,
    which compiles to an empty expression and renders nothing — a policy
    that looks configured and does nothing at all.

    The fingerprint store is not group-scoped (one row per MAC,
    platform-wide), so these counts are platform-wide too. ``group_id`` is
    validated so the endpoint 404s consistently with its siblings rather
    than answering for a group that does not exist.
    """
    await _get_group(db, group_id)

    res = await db.execute(
        select(
            DHCPFingerprint.fingerbank_device_class,
            func.count().label("device_count"),
            func.count(
                func.distinct(
                    func.concat(
                        func.coalesce(DHCPFingerprint.option_55, ""),
                        "|",
                        func.coalesce(DHCPFingerprint.option_60, ""),
                    )
                )
            ).label("signature_count"),
            func.max(DHCPFingerprint.fingerbank_score).label("best_score"),
            func.avg(DHCPFingerprint.fingerbank_score).label("avg_score"),
        )
        .where(DHCPFingerprint.fingerbank_device_class.isnot(None))
        .where(DHCPFingerprint.fingerbank_device_class != "")
        .group_by(DHCPFingerprint.fingerbank_device_class)
        .order_by(func.count().desc())
    )
    classes = [
        DeviceObservationOut(
            device_class=row[0],
            device_count=row[1],
            signature_count=row[2],
            best_score=int(row[3]) if row[3] is not None else None,
            avg_score=int(row[4]) if row[4] is not None else None,
        )
        for row in res.all()
    ]

    totals = await db.execute(select(func.count()).select_from(DHCPFingerprint))
    total = int(totals.scalar() or 0)
    classified = sum(c.device_count for c in classes)

    return DeviceObservationsOut(
        classes=classes,
        unclassified_devices=total - classified,
        total_devices=total,
        note=(
            "Classes come from fingerprints already observed and enriched. A "
            "device class absent here has not been seen on this network yet, so "
            "a policy naming it will match nothing until one appears. Scores are "
            "fingerbank's own 0-100 confidence: a low one usually means it fell "
            "back to the MAC vendor instead of identifying the device, so that "
            "class groups unrelated hardware and makes a poor policy target."
        ),
    )
