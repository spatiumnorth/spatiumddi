"""Signals recorded from handlers rather than from the request hook (#3651)."""

from __future__ import annotations

from app.services.web_exposure import store
from app.services.web_exposure.classify import bucket_of, classify, is_private_fast
from app.services.web_exposure.config import get_runtime_config


async def note_login_failure(ip: str | None, username: str) -> None:
    """Count a failed sign-in from an external source. Called from the one
    place every failed sign-in is audited. Never raises."""
    try:
        if not ip or is_private_fast(ip):
            return
        rt = await get_runtime_config()
        if not rt.enabled or classify(ip, rt.trusted) != "external":
            return
        bucket = bucket_of(ip)
        if bucket:
            store.record(
                bucket,
                ip,
                store.SIGNAL_LOGIN_FAILURE,
                path="/api/v1/auth/login",
                username=username,
            )
            from app.services.web_exposure import mitigations  # noqa: PLC0415

            ban = await mitigations.register_failure(ip)
            if ban is not None:
                await _audit_ban(ban)
    except Exception:  # noqa: BLE001 — detection never fails a sign-in
        return


async def _audit_ban(ban: dict[str, object]) -> None:
    """A ban is an enforcement decision taken by the system, so it is audited
    (non-negotiable #4) in its own transaction, not the failed sign-in's."""
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.audit import AuditLog  # noqa: PLC0415

    try:
        async with AsyncSessionLocal() as db:
            db.add(
                AuditLog(
                    user_display_name="system",
                    auth_source="system",
                    action="web_exposure.ban",
                    resource_type="web_exposure",
                    resource_id=str(ban["bucket"]),
                    resource_display=f"source ban {ban['bucket']}",
                    result="success",
                    new_value={
                        "bucket": ban["bucket"],
                        "minutes": ban["minutes"],
                        "level": ban["level"],
                        "failures": ban["failures"],
                    },
                )
            )
            await db.commit()
    except Exception:  # noqa: BLE001 — the ban stands even if its row cannot be written
        return
