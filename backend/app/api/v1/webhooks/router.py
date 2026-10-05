"""``/api/v1/webhooks`` — typed-event subscription CRUD + delivery
inspection.

Distinct from the audit-forward surface under ``/settings/audit-
forward-targets``. Audit-forward fires on every audit row in a syslog
/ webhook / SMTP wire format the operator picks; this surface emits
**typed events** (``subnet.created``, ``ip.allocated``, …) shaped for
downstream automation, with HMAC signing and an outbox-backed
delivery queue.

Endpoints:

* ``GET /webhooks/event-types`` — vocabulary the platform emits.
* ``GET /webhooks`` / ``POST /webhooks`` / ``GET /webhooks/{id}`` /
  ``PUT /webhooks/{id}`` / ``DELETE /webhooks/{id}`` — subscription
  CRUD.
* ``POST /webhooks/{id}/test`` — synthesize a test event and push it
  through the same delivery path the worker uses (with HMAC + retry
  state). Result returned synchronously so the operator sees status
  + body without round-tripping the outbox.
* ``GET /webhooks/{id}/deliveries`` — recent ``EventOutbox`` rows for
  one subscription, including dead-letter rows.
* ``POST /webhooks/deliveries/{id}/retry`` — flip a dead/failed row
  back to ``pending`` so the next worker tick re-tries.
"""

from __future__ import annotations

import secrets as _secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc, select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.core.crypto import decrypt_str, encrypt_dict, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.models.event_subscription import EventOutbox, EventSubscription
from app.services import event_delivery
from app.services.event_publisher import (
    _RESOURCE_NAMESPACE,
    _SPECIAL_EVENT_MAP,
    _VERB_MAP,
)

router = APIRouter(tags=["webhooks"])


# ── Schemas ────────────────────────────────────────────────────────────────


class WebhookSubscriptionWrite(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=1000)
    enabled: bool = True
    url: str = Field(..., min_length=1, max_length=1024)
    # ``None`` on update means "keep existing", ``""`` means "clear",
    # any other string is encrypted and stored. On create, ``None``
    # auto-generates a 32-byte random secret and returns it ONCE in
    # the response (``secret_plaintext``).
    secret: str | None = None
    event_types: list[str] | None = None
    # Write-only (#1579, mirroring the #1506 contract): on update,
    # ``None`` (or omitted) keeps the stored headers, ``{}`` clears
    # them, any other dict replaces them. Values are Fernet-encrypted
    # at rest and never returned — responses carry header names plus a
    # ``headers_set`` flag only.
    headers: dict[str, str] | None = None
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    max_attempts: int = Field(default=8, ge=1, le=20)

    @field_validator("url")
    @classmethod
    def _v_url(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("url must start with http:// or https://")
        return v


class WebhookSubscriptionResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    url: str
    secret_set: bool
    event_types: list[str] | None
    # Header VALUES are credentials (#1579) and are never returned —
    # only their names, so the operator can still see which headers a
    # subscription sends, plus whether any are stored at all.
    header_names: list[str]
    headers_set: bool
    timeout_seconds: int
    max_attempts: int
    created_at: datetime
    modified_at: datetime
    # Plaintext secret — populated **only** in the create response.
    # Server never re-exposes it after that. The receiver should grab
    # it from this field and store it; lose it and the operator has to
    # rotate via PUT.
    secret_plaintext: str | None = None

    model_config = {"from_attributes": True}


class WebhookDeliveryResponse(BaseModel):
    id: uuid.UUID
    subscription_id: uuid.UUID
    event_type: str
    state: str
    attempts: int
    next_attempt_at: datetime
    last_error: str | None
    last_status_code: int | None
    delivered_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Helpers ────────────────────────────────────────────────────────────────


def _header_names(sub: EventSubscription) -> list[str]:
    """Sorted custom-header names for the response — never the values
    (#1579). A value that won't decrypt yields no names rather than an
    error: the list endpoint shouldn't 500 over one bad row, and the
    delivery path reports the decrypt failure on its own."""
    try:
        return sorted(event_delivery.subscription_headers(sub))
    except Exception:  # noqa: BLE001
        return []


def _to_response(
    sub: EventSubscription, *, secret_plaintext: str | None = None
) -> WebhookSubscriptionResponse:
    return WebhookSubscriptionResponse(
        id=sub.id,
        name=sub.name,
        description=sub.description,
        enabled=sub.enabled,
        url=sub.url,
        secret_set=bool(sub.secret_encrypted),
        event_types=list(sub.event_types) if sub.event_types else None,
        header_names=_header_names(sub),
        headers_set=bool(sub.headers_encrypted),
        timeout_seconds=sub.timeout_seconds,
        max_attempts=sub.max_attempts,
        created_at=sub.created_at,
        modified_at=sub.modified_at,
        secret_plaintext=secret_plaintext,
    )


def _apply_body(
    sub: EventSubscription,
    body: WebhookSubscriptionWrite,
    *,
    creating: bool,
) -> str | None:
    """Apply the request body to the row. Returns the cleartext secret
    iff one was newly assigned (so the caller can return it once)."""
    sub.name = body.name
    sub.description = body.description
    sub.enabled = body.enabled
    sub.url = body.url
    sub.event_types = body.event_types or None
    # Headers are write-only (#1579): ``None`` keeps the stored dict on
    # update (on create it simply means "none"), ``{}`` clears it, and
    # a non-empty dict is encrypted and stored.
    if creating:
        sub.headers_encrypted = encrypt_dict(body.headers) if body.headers else None
    elif body.headers is not None:
        sub.headers_encrypted = encrypt_dict(body.headers) if body.headers else None
    sub.timeout_seconds = body.timeout_seconds
    sub.max_attempts = body.max_attempts

    if creating:
        # Auto-generate a secret if the operator didn't supply one;
        # exposing one strong key-rotation default is friendlier than
        # forcing them to think about entropy at create time.
        plaintext = body.secret if body.secret else _secrets.token_urlsafe(32)
        sub.secret_encrypted = encrypt_str(plaintext) if plaintext else None
        return plaintext
    if body.secret is not None:
        sub.secret_encrypted = encrypt_str(body.secret) if body.secret else None
        return body.secret if body.secret else None
    return None


# ── CRUD ──────────────────────────────────────────────────────────────────


@router.get("/event-types")
async def list_event_types(_: CurrentUser) -> dict[str, list[str]]:
    """Return the typed-event vocabulary the platform emits.

    Operators use this to populate the multi-select on the
    subscription editor. Generated from the same mapping the publisher
    uses (``_RESOURCE_NAMESPACE`` × ``_VERB_MAP``) so the surface
    stays in lock-step with what's actually fired.
    """
    types: set[str] = set()
    for namespace in set(_RESOURCE_NAMESPACE.values()):
        for verb in _VERB_MAP.values():
            types.add(f"{namespace}.{verb}")
    # Special-cased event names override the synthesised ``ns.verb``
    # for cases like ``system.backup_completed`` that don't fit the
    # create/update/delete trio. Surface them in the catalog so
    # operators can subscribe.
    types.update(_SPECIAL_EVENT_MAP.values())
    return {"event_types": sorted(types)}


@router.get("", response_model=list[WebhookSubscriptionResponse])
async def list_subscriptions(_user: SuperAdmin, db: DB) -> list[WebhookSubscriptionResponse]:
    res = await db.execute(select(EventSubscription).order_by(EventSubscription.name))
    return [_to_response(s) for s in res.scalars().all()]


@router.post(
    "",
    response_model=WebhookSubscriptionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_subscription(
    body: WebhookSubscriptionWrite, _user: SuperAdmin, db: DB
) -> WebhookSubscriptionResponse:
    forbid_in_demo_mode("Webhook subscription creation is disabled")
    sub = EventSubscription()
    plaintext = _apply_body(sub, body, creating=True)
    db.add(sub)
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"create failed: {exc}") from exc
    await db.refresh(sub)
    return _to_response(sub, secret_plaintext=plaintext)


@router.get("/{sub_id}", response_model=WebhookSubscriptionResponse)
async def get_subscription(
    sub_id: uuid.UUID, _user: SuperAdmin, db: DB
) -> WebhookSubscriptionResponse:
    sub = await db.get(EventSubscription, sub_id)
    if sub is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return _to_response(sub)


@router.put("/{sub_id}", response_model=WebhookSubscriptionResponse)
async def update_subscription(
    sub_id: uuid.UUID,
    body: WebhookSubscriptionWrite,
    _user: SuperAdmin,
    db: DB,
) -> WebhookSubscriptionResponse:
    forbid_in_demo_mode("Webhook subscription updates are disabled")
    sub = await db.get(EventSubscription, sub_id)
    if sub is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    plaintext = _apply_body(sub, body, creating=False)
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"update failed: {exc}") from exc
    await db.refresh(sub)
    return _to_response(sub, secret_plaintext=plaintext)


@router.delete("/{sub_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_subscription(sub_id: uuid.UUID, _user: SuperAdmin, db: DB) -> None:
    sub = await db.get(EventSubscription, sub_id)
    if sub is None:
        return
    await db.delete(sub)
    await db.commit()


# ── Test + delivery inspection ─────────────────────────────────────────────


class TestResult(BaseModel):
    status: str  # "ok" | "error"
    status_code: int | None
    error: str | None


@router.post("/{sub_id}/test", response_model=TestResult)
async def test_subscription(
    sub_id: uuid.UUID, current_user: CurrentUser, _su: SuperAdmin, db: DB
) -> TestResult:
    """Push a synthetic event through the same signing + transport path
    the worker uses. Doesn't write to the outbox — explicit probe
    traffic, not retry-able. Returns the delivery outcome inline so
    the operator sees a 2xx vs error immediately."""
    sub = await db.get(EventSubscription, sub_id)
    if sub is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    secret = ""
    if sub.secret_encrypted:
        try:
            secret = decrypt_str(sub.secret_encrypted)
        except Exception as exc:  # noqa: BLE001
            return TestResult(
                status="error",
                status_code=None,
                error=f"secret decrypt failed: {exc}",
            )

    fake_id = uuid.uuid4()
    fake_payload: dict[str, Any] = {
        "event_id": str(fake_id),
        "event_type": "test.ping",
        "occurred_at": datetime.now(UTC).isoformat(),
        "actor": {
            "user_id": str(current_user.id),
            "display_name": current_user.display_name,
            "auth_source": "local",
        },
        "resource": {
            "type": "event_subscription",
            "id": str(sub.id),
            "display": sub.name,
        },
        "action": "test_ping",
        "result": "success",
        "old_value": None,
        "new_value": None,
        "changed_fields": [],
    }
    # In-memory EventOutbox stand-in so we can reuse ``_deliver_one``.
    fake_row = EventOutbox(
        id=fake_id,
        subscription_id=sub.id,
        event_type="test.ping",
        payload=fake_payload,
        state="in_flight",
        attempts=0,
        next_attempt_at=datetime.now(UTC),
    )

    import httpx as _httpx

    async with _httpx.AsyncClient() as client:
        status_code, error = await event_delivery._deliver_one(  # noqa: SLF001
            client, sub, fake_row, secret, "dev"
        )
    return TestResult(
        status="ok" if error is None else "error",
        status_code=status_code,
        error=error,
    )


@router.get("/{sub_id}/deliveries", response_model=list[WebhookDeliveryResponse])
async def list_deliveries(
    sub_id: uuid.UUID, _user: SuperAdmin, db: DB, limit: int = 100
) -> list[WebhookDeliveryResponse]:
    """Latest ``EventOutbox`` rows for one subscription. Includes
    dead-letter rows so the operator can see + retry them."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    res = await db.execute(
        select(EventOutbox)
        .where(EventOutbox.subscription_id == sub_id)
        .order_by(desc(EventOutbox.created_at))
        .limit(limit)
    )
    return [
        WebhookDeliveryResponse.model_validate(r, from_attributes=True) for r in res.scalars().all()
    ]


@router.post(
    "/deliveries/{delivery_id}/retry",
    response_model=WebhookDeliveryResponse,
)
async def retry_delivery(
    delivery_id: uuid.UUID, _user: SuperAdmin, db: DB
) -> WebhookDeliveryResponse:
    row = await db.get(EventOutbox, delivery_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Delivery not found")
    if row.state == "delivered":
        raise HTTPException(
            status_code=409,
            detail="Delivery already succeeded — nothing to retry",
        )
    await event_delivery.reset_outbox_row(db, row)
    await db.commit()
    await db.refresh(row)
    return WebhookDeliveryResponse.model_validate(row, from_attributes=True)
