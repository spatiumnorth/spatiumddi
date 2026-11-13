"""One place that writes the ``denied`` audit row for a handler-level 403 (#3644).

A router-level gate (``require_permission`` and friends) writes a ``denied``
audit row before it raises. A refusal decided inside a handler (``if not
user_has_permission(...): raise HTTPException(403)``) used to write nothing,
so the same probe was visible or invisible depending on where the check
happened to live. Rather than editing every such site, the 403
``HTTPException`` handler registered in :func:`app.main.create_app` calls
:func:`audit_unrecorded_denial`, which writes the row when

* the caller was authenticated (:func:`remember_caller`, called by the bearer
  authentication, took a snapshot of who they are), and
* no denial row was already written for this request
  (:func:`note_denial_audited`, called by every recorder that writes one).

A 403 raised while authenticating (disabled account, password change
required) has no snapshot yet, so it is not audited here.

The row is written in a session of its own: the request's transaction is
rolled back by the time a handler's exception reaches the handler.
Best-effort: a failure to audit never changes the 403.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

import structlog
from fastapi import Request

from app.core.request_meta import clean_user_agent, get_trusted_client_ip
from app.db import AsyncSessionLocal, get_db
from app.models.audit import AuditLog

logger = structlog.get_logger(__name__)

# A ContextVar rather than ``request.state``: the step-up helper writes its
# own denied row and has no request to hand. Reset by ``remember_caller`` at
# the start of every authenticated request.
_denial_audited: ContextVar[bool] = ContextVar("denial_audited", default=False)

_CALLER_KEY = "audit_caller"


def remember_caller(request: Request, user: Any) -> None:
    """Snapshot who the caller is, as plain values: by the time a 403 reaches
    the handler the request's session is rolled back and ``user`` is expired."""
    _denial_audited.set(False)
    request.state.__setattr__(
        _CALLER_KEY,
        {
            "user_id": user.id,
            "user_display_name": user.display_name,
            "auth_source": getattr(user, "auth_source", "local") or "local",
        },
    )


def note_denial_audited() -> None:
    """Record that a ``denied`` row was written for this request, so the 403
    handler does not write a second one."""
    _denial_audited.set(True)


async def audit_unrecorded_denial(request: Request, detail: Any) -> None:
    """Write the ``denied`` row for a handler-level 403 that has none."""
    caller = getattr(request.state, _CALLER_KEY, None)
    if caller is None or _denial_audited.get():
        return
    _denial_audited.set(True)
    method = request.method.upper()
    path = request.url.path
    row = AuditLog(
        user_id=caller["user_id"],
        user_display_name=caller["user_display_name"],
        auth_source=caller["auth_source"],
        source_ip=get_trusted_client_ip(request),
        user_agent=clean_user_agent(request.headers.get("user-agent")),
        action=_action(request),
        resource_type="endpoint",
        resource_id=path,
        resource_display=f"{method} {path}",
        result="denied",
        error_detail=str(detail)[:500],
    )
    try:
        override = request.app.dependency_overrides.get(get_db)
        if override is not None:
            # Tests substitute one shared session; use it as the dependency would.
            gen = override()
            db = await gen.__anext__()
            try:
                db.add(row)
                await db.commit()
            finally:
                await gen.aclose()
        else:
            async with AsyncSessionLocal() as db:
                db.add(row)
                await db.commit()
    except Exception as exc:  # noqa: BLE001 — never let the audit change the 403
        logger.warning("permission_audit_write_failed", error=str(exc))


def _action(request: Request) -> str:
    from app.core.permissions import method_action_for_request  # noqa: PLC0415

    return method_action_for_request(request)
