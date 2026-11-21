"""Live reverse-DNS source for DNS query-log client names (#4249).

Kept apart from ``client_names`` on purpose: this is the only code that sends
PTR queries, and only the REST route injects it. The Copilot tools must not
reach it (they declare no outbound budget).
"""

from __future__ import annotations

import asyncio
import time

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.settings import PlatformSettings
from app.services.ipam.reverse_dns import _build_resolver, resolve_ptr

PTR_CACHE_TTL_SECONDS = 300.0
PTR_CACHE_MAX = 4096
PTR_CONCURRENCY = 16

# ip -> (monotonic expiry, name or None). A miss is cached too.
_ptr_cache: dict[str, tuple[float, str | None]] = {}


def invalidate_cache() -> None:
    _ptr_cache.clear()


async def resolve_ptr_batch(db: AsyncSession, ips: list[str]) -> dict[str, str]:
    now = time.monotonic()
    found: dict[str, str] = {}
    todo: list[str] = []
    for ip in ips:
        hit = _ptr_cache.get(ip)
        if hit is not None and hit[0] > now:
            if hit[1]:
                found[ip] = hit[1]
        else:
            todo.append(ip)
    if not todo:
        return found
    ps = await db.get(PlatformSettings, 1)
    resolver = _build_resolver((ps.reverse_dns_resolvers if ps else None) or None)
    if resolver is None:
        return found
    sem = asyncio.Semaphore(PTR_CONCURRENCY)

    async def _one(ip: str) -> tuple[str, str | None]:
        async with sem:
            return ip, await resolve_ptr(ip, resolver)

    results = await asyncio.gather(*[_one(ip) for ip in todo])
    if len(_ptr_cache) + len(results) > PTR_CACHE_MAX:
        _ptr_cache.clear()
    expiry = time.monotonic() + PTR_CACHE_TTL_SECONDS
    for ip, name in results:
        _ptr_cache[ip] = (expiry, name)
        if name:
            found[ip] = name
    return found
