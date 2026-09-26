"""Daily "is there a newer release on GitHub?" task.

Fires once per day from Celery Beat. Gates on
``PlatformSettings.github_release_check_enabled`` so operators can
disable the check entirely (air-gapped deployments, forks). Queries
``api.github.com/repos/{github_repo}/releases/latest`` anonymously —
the unauthenticated rate limit (60/hour/IP) is plenty for a once-a-day
check and we intentionally don't require a token.

**Version comparison.** Through :mod:`app.core.versions` (#1182), never
as strings: releases are CalVer (``YYYY.MM.DD-N``) until 1.0.0 and SemVer
from it, and ``"1.0.0" > "2026.09.04-1"`` is false as a string. A running
build that is not a release (``dev``, ``latest``, ``dev-<sha>-<rand>``, a
``0.x`` placeholder) is unknown, and sees ``update_available=True`` once a
release exists — the operator already knows they're on an untagged build.
A nightly has every CalVer release tagged before the day it was built, so
it is offered only the ones tagged later; a SemVer tag carries no date, so
a nightly is always offered one.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.core.versions import includes_release, parse_release
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1
_HTTP_TIMEOUT_SECONDS = 10


def _normalize(v: str | None) -> str:
    """Strip whitespace and a leading ``v``: a tag may be published as
    ``v2026.09.04-1`` or ``v1.0.0``."""
    if not v:
        return ""
    return v.strip().lstrip("v")


def _is_newer(latest: str, running: str) -> bool:
    """Return True when ``latest`` is strictly newer than ``running``.

    ``latest`` must name a release, or there is nothing to offer. A
    ``running`` build that is not a release is treated as outdated unless
    it is a nightly known to include ``latest``: the local-build fallback
    should surface the update pill so the operator knows a tagged release
    is out.
    """
    lat = _normalize(latest)
    latest_release = parse_release(lat)
    if latest_release is None:
        return False
    run = _normalize(running)
    running_release = parse_release(run)
    if running_release is not None:
        return latest_release > running_release
    return includes_release(run, lat) is not True


async def _run_check() -> dict[str, Any]:
    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _SINGLETON_ID)
            if ps is None:
                return {"status": "no_settings_row"}
            if not ps.github_release_check_enabled:
                return {"status": "disabled"}

            url = f"https://api.github.com/repos/{settings.github_repo}/releases/latest"
            now = datetime.now(UTC)
            try:
                # follow_redirects: GitHub answers 301 for a repo that has moved — which
                # an org rename makes routine. httpx does not follow by default and
                # raise_for_status() does not reject a 3xx, so the redirect BODY was
                # parsed as a release: no tag_name, so the check recorded "up to date"
                # with no error and logged success. A silent false negative on an
                # update notifier is worse than a loud failure; following the redirect
                # removes it and keeps a stale github_repo working.
                async with httpx.AsyncClient(
                    timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=True
                ) as client:
                    resp = await client.get(
                        url,
                        headers={"Accept": "application/vnd.github+json"},
                    )
                if resp.status_code == 404:
                    # Repo has no published releases yet. Distinct from
                    # an error — clear any prior error and record the
                    # successful probe.
                    ps.latest_version = None
                    ps.update_available = False
                    ps.latest_release_url = None
                    ps.latest_check_error = None
                    ps.latest_checked_at = now
                    await db.commit()
                    return {"status": "no_releases"}
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as exc:
                ps.latest_check_error = f"HTTP {exc.response.status_code}"
                ps.latest_checked_at = now
                await db.commit()
                logger.warning(
                    "update_check_http_error",
                    status=exc.response.status_code,
                    url=url,
                )
                return {"status": "http_error", "code": exc.response.status_code}
            except (httpx.RequestError, ValueError) as exc:
                # RequestError covers DNS / connect / read errors;
                # ValueError covers JSON-decode issues. Either way we
                # surface the message so the UI can explain the stale
                # check.
                ps.latest_check_error = str(exc)[:500]
                ps.latest_checked_at = now
                await db.commit()
                logger.warning("update_check_network_error", error=str(exc))
                return {"status": "network_error", "error": str(exc)}

            tag = (data.get("tag_name") or "").strip()
            html_url = data.get("html_url") or None
            ps.latest_version = tag or None
            ps.update_available = _is_newer(tag, settings.version)
            ps.latest_release_url = html_url
            ps.latest_check_error = None
            ps.latest_checked_at = now
            await db.commit()
            logger.info(
                "update_check_ok",
                running=settings.version,
                latest=tag,
                update_available=ps.update_available,
            )
            return {
                "status": "ok",
                "running": settings.version,
                "latest": tag,
                "update_available": ps.update_available,
            }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.update_check.check_github_release",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    max_retries=2,
)
def check_github_release(self: Any) -> dict[str, Any]:  # noqa: ARG001
    """Beat-fired entrypoint. Runs the async checker under asyncio."""
    return asyncio.run(_run_check())


__all__ = ["check_github_release"]
