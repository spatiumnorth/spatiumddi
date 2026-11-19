"""Firewall block-list feed CRUD + token reveal + the public poll endpoint (#606).

Two routers ship from here:

* ``router`` — the admin CRUD surface (Fernet-encrypted token, one-time reveal
  on create + a password-confirmed reveal endpoint), gated at include time by
  the ``security.firewall_feeds`` feature module + ``firewall_feed`` permission.
* ``public_router`` — the UNAUTHENTICATED ``GET /{id}/blocklist.txt`` a polling
  firewall hits, authorised by the per-feed token (``?token=`` or bearer). It
  carries NO session/permission/module dependency so a firewall can always
  reach it; it renders the active ``NetworkBlock`` set as plain text.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.stepup import require_operator_stepup
from app.core.crypto import encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import require_resource_permission
from app.core.request_meta import get_trusted_client_ip
from app.models.audit import AuditLog
from app.models.firewall_feed import FIREWALL_FEED_KINDS, FirewallFeed
from app.services.firewall_feeds.service import (
    feed_token,
    generate_feed_token,
    record_poll,
    render_blocklist,
    verify_feed_token,
)

router = APIRouter(
    tags=["firewall-feeds"],
    dependencies=[Depends(require_resource_permission("firewall_feed"))],
)
public_router = APIRouter(tags=["firewall-feeds"])


def _poll_path(feed_id: uuid.UUID, token: str) -> str:
    return f"/api/v1/firewall-feeds/feeds/{feed_id}/blocklist.txt?token={token}"


# ── Schemas ──────────────────────────────────────────────────────────


class FeedCreate(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    kind: str = "ip"

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name is required")
        return v

    @field_validator("kind")
    @classmethod
    def _valid_kind(cls, v: str) -> str:
        if v not in FIREWALL_FEED_KINDS:
            raise ValueError(f"kind must be one of {FIREWALL_FEED_KINDS}")
        return v


class FeedUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None


class FeedResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    kind: str
    poll_path: str  # path WITHOUT the token — the reveal endpoint returns the full URL
    last_polled_at: datetime | None
    last_polled_ip: str | None
    poll_count: int
    created_at: datetime
    modified_at: datetime


class FeedTokenResponse(BaseModel):
    token: str
    poll_path: str  # full path incl. ?token=


class CreatedFeedResponse(BaseModel):
    feed: FeedResponse
    token: str
    poll_path: str


class RevealRequest(BaseModel):
    password: str | None = None
    totp_code: str | None = None


def _to_response(f: FirewallFeed) -> FeedResponse:
    return FeedResponse(
        id=f.id,
        name=f.name,
        description=f.description,
        enabled=f.enabled,
        kind=f.kind,
        poll_path=f"/api/v1/firewall-feeds/feeds/{f.id}/blocklist.txt",
        last_polled_at=f.last_polled_at,
        last_polled_ip=str(f.last_polled_ip) if f.last_polled_ip else None,
        poll_count=f.poll_count or 0,
        created_at=f.created_at,
        modified_at=f.modified_at,
    )


def _audit(
    db: Any, *, user: Any, action: str, feed_id: uuid.UUID, feed_name: str, result: str = "success"
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="firewall_feed",
            resource_id=str(feed_id),
            resource_display=feed_name,
            result=result,
        )
    )


# ── Admin CRUD ───────────────────────────────────────────────────────


@router.get("/feeds", response_model=list[FeedResponse])
async def list_feeds(db: DB, _: CurrentUser) -> list[FeedResponse]:
    res = await db.execute(select(FirewallFeed).order_by(FirewallFeed.name))
    return [_to_response(f) for f in res.scalars().all()]


@router.post("/feeds", response_model=CreatedFeedResponse, status_code=status.HTTP_201_CREATED)
async def create_feed(body: FeedCreate, db: DB, user: SuperAdmin) -> CreatedFeedResponse:
    forbid_in_demo_mode("Firewall feed creation is disabled")
    existing = await db.execute(select(FirewallFeed).where(FirewallFeed.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A firewall feed with that name exists")

    token = generate_feed_token()
    f = FirewallFeed(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        kind=body.kind,
        token_encrypted=encrypt_str(token),
    )
    db.add(f)
    await db.flush()
    _audit(db, user=user, action="firewall_feed_create", feed_id=f.id, feed_name=f.name)
    await db.commit()
    await db.refresh(f)
    return CreatedFeedResponse(feed=_to_response(f), token=token, poll_path=_poll_path(f.id, token))


@router.put("/feeds/{feed_id}", response_model=FeedResponse)
async def update_feed(
    feed_id: uuid.UUID, body: FeedUpdate, db: DB, user: SuperAdmin
) -> FeedResponse:
    f = await db.get(FirewallFeed, feed_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Firewall feed not found")
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(f, k, v)
    _audit(db, user=user, action="firewall_feed_update", feed_id=f.id, feed_name=f.name)
    await db.commit()
    await db.refresh(f)
    return _to_response(f)


@router.delete("/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_feed(feed_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    f = await db.get(FirewallFeed, feed_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Firewall feed not found")
    _audit(db, user=user, action="firewall_feed_delete", feed_id=f.id, feed_name=f.name)
    await db.delete(f)
    await db.commit()


@router.post("/feeds/{feed_id}/reveal", response_model=FeedTokenResponse)
async def reveal_token(
    feed_id: uuid.UUID, body: RevealRequest, db: DB, user: SuperAdmin
) -> FeedTokenResponse:
    """Reveal the feed token after re-confirming the operator (password / TOTP),
    so they can build the poll URL to paste into the firewall. Audited."""
    f = await db.get(FirewallFeed, feed_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Firewall feed not found")
    # #1413 — through the shared step-up, so a wrong answer spends the
    # per-account budget like every other step-up.
    await require_operator_stepup(
        db,
        user,
        password=body.password,
        totp_code=body.totp_code,
        action="firewall_feed_reveal_denied",
        resource_type="firewall_feed",
        resource_id=str(f.id),
        resource_display=f.name,
    )
    token = feed_token(f)
    _audit(db, user=user, action="firewall_feed_reveal", feed_id=f.id, feed_name=f.name)
    await db.commit()
    return FeedTokenResponse(token=token, poll_path=_poll_path(f.id, token))


@router.post("/feeds/{feed_id}/rotate-token", response_model=FeedTokenResponse)
async def rotate_token(feed_id: uuid.UUID, db: DB, user: SuperAdmin) -> FeedTokenResponse:
    """Mint a fresh token (invalidates the old poll URL). The firewall must be
    updated with the new URL."""
    forbid_in_demo_mode("Firewall feed token rotation is disabled")
    f = await db.get(FirewallFeed, feed_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Firewall feed not found")
    token = generate_feed_token()
    f.token_encrypted = encrypt_str(token)
    _audit(db, user=user, action="firewall_feed_rotate_token", feed_id=f.id, feed_name=f.name)
    await db.commit()
    return FeedTokenResponse(token=token, poll_path=_poll_path(f.id, token))


# ── Public poll endpoint (token-authed, no session) ──────────────────


@public_router.get("/feeds/{feed_id}/blocklist.txt", response_class=PlainTextResponse)
async def poll_blocklist(
    feed_id: uuid.UUID,
    request: Request,
    db: DB,
    token: str | None = Query(default=None),
) -> PlainTextResponse:
    """Serve the feed body to a polling firewall. Token via ``?token=`` or an
    ``Authorization: Bearer`` header. No session — the token is the auth."""
    f = await db.get(FirewallFeed, feed_id)
    if f is None or not f.enabled:
        # Uniform 404 whether the feed is missing or disabled — don't leak state.
        raise HTTPException(status_code=404, detail="feed not found")

    presented = token
    if not presented:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            presented = auth[7:].strip()
    if not verify_feed_token(f, presented):
        raise HTTPException(status_code=401, detail="invalid or missing token")

    body = await render_blocklist(db, f)
    # Provenance IP the operator sees for "who polled this feed" — use the
    # unspoofable X-Real-IP so a client can't forge last_polled_ip (#626).
    source_ip = get_trusted_client_ip(request)
    await record_poll(db, f, source_ip)
    await db.commit()
    return PlainTextResponse(content=body, media_type="text/plain")


__all__ = ["public_router", "router"]
