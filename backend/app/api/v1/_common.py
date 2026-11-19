"""Response models shared by routes whose payload is the same everywhere
(issue #917).

A route with no ``response_model`` publishes ``{}`` as its response schema, so
a generated client gets an untyped container and every field access becomes
stringly-typed. That is the same silent-drift failure #907 fixed for nullable
properties, arriving through a different door — and it was true of ~113 routes,
most of them these two or three shapes repeated.

Declaring them once also pins the shapes: six ``bulk-delete`` routes returned
``{"deleted": n, "not_found": [...]}`` by convention alone, with nothing to
stop the seventh from spelling it differently.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.auth import User


class StatusResponse(BaseModel):
    """A fire-and-forget acknowledgement.

    ``status`` is the operative field; ``task_id`` is present on the routes
    that hand work to Celery and is an empty string when the broker was
    unreachable — which the callers already relied on, so it stays that way
    rather than becoming ``null`` and breaking them.
    """

    status: str = Field(description="e.g. 'queued', 'ok', 'broker_unavailable'")
    task_id: str | None = Field(
        default=None,
        description="Celery task id when the route enqueued work; '' if the broker was down.",
    )
    detail: str | None = Field(default=None, description="Optional human-readable note.")


class BulkDeleteResponse(BaseModel):
    """Result of a bulk soft-delete.

    ``not_found`` carries the ids that matched nothing — a partial success is
    the normal case when a client deletes from a stale list, and it must be
    distinguishable from a total one.
    """

    deleted: int = Field(description="How many rows were deleted.")
    not_found: list[uuid.UUID] = Field(
        default_factory=list, description="Requested ids that matched no live row."
    )


__all__ = ["BulkDeleteResponse", "StatusResponse"]


def add_trigger_audit(
    db: AsyncSession,
    user: User,
    *,
    resource_type: str,
    resource_id: object,
    resource_display: str,
    action: str = "trigger",
    new_value: dict | None = None,
) -> None:
    """Stage the audit row for an operator-triggered background job (#2303).

    The work itself runs on a Celery worker, where the reconcilers can only
    attribute their own rows to ``system``; this row is what records WHO asked.
    Caller commits it before enqueueing so it is durable before the response
    returns (non-negotiable #4).
    """
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            resource_display=resource_display,
            new_value=new_value,
        )
    )


class WinRMSettings(BaseModel):
    """The non-secret WinRM connection settings stored for a Windows DNS or
    Windows DHCP server, as the next WinRM call will use them.

    Returned so an edit dialog can show — and an untouched save keep — what is
    stored. The username and password are never returned.
    """

    winrm_port: int
    transport: str = Field(description="ntlm | credssp | basic")
    use_tls: bool
    verify_tls: bool


def winrm_settings_from_blob(credentials_encrypted: bytes | None) -> WinRMSettings | None:
    """Echo the stored WinRM settings, or None when nothing readable is stored.

    Best-effort: an undecryptable blob (key rotation, a restore without
    rewrap) yields None rather than failing the listing that carries it.
    """
    if not credentials_encrypted:
        return None
    from app.core.crypto import decrypt_dict  # noqa: PLC0415
    from app.drivers._winrm import effective_winrm_settings  # noqa: PLC0415

    try:
        creds = decrypt_dict(credentials_encrypted)
    except Exception:  # noqa: BLE001 — never break the listing on a bad blob
        return None
    return WinRMSettings(**effective_winrm_settings(creds))
