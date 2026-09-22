"""Stored DNS agent config bundles (#1111) — what the long-poll serves.

The bundle a DNS agent receives used to be assembled inside the api request
path, once per agent long-poll that observed a change (and once per page
while ops were pending), with peak memory proportional to the group's
record count. It is now rendered once per (server, watermark) — by the
worker, or inline by the api during the migration release — serialised
once in the #958 wire shape, gzip-compressed and stored here; the
long-poll reads one small row per wake and streams the stored bytes when
it answers 200.

Two integers on ``dns_server`` decide whether a stored bundle is current
(``is_current``): ``bundle_dirty_seq`` is bumped in the transaction of
every change that feeds the bundle (``services.dns.bundle_dirty``), and
``bundle_watermark`` is the sequence the newest stored bundle was rendered
at. No assembly and no content hash are involved in that check.
"""

from __future__ import annotations

import gzip
import json
import uuid
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.dns import DNSAgentBundle, DNSServer

logger = structlog.get_logger(__name__)

RENDERED_BY_WORKER = "worker"
RENDERED_BY_API = "api"

RENDER_STATUS_OK = "ok"
RENDER_STATUS_FAILED = "failed"

# Keys the long-poll splices in per request. Never part of the stored body.
DYNAMIC_KEYS: tuple[str, ...] = ("etag", "pending_record_ops", "pending_ops_remaining")

_MAX_ERROR = 2000


def is_current(server: DNSServer) -> bool:
    """True when the newest stored bundle reflects every change made so far."""
    return (
        server.bundle_watermark is not None and server.bundle_watermark >= server.bundle_dirty_seq
    )


def encode_body(body: Any) -> bytes:
    """Serialise ``body`` (a JSON value — the bundle body, or the ops page)
    exactly as the route sends it on the wire.

    These are Starlette ``JSONResponse.render``'s kwargs, not ``json.dumps``'s
    defaults (#958): compact separators, raw UTF-8, no bare ``NaN``.
    ``default=str`` matches what ``_compute_etag`` hashes, so the body and
    the ETag stay consistent.
    """
    return json.dumps(
        body,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def compress_body(body_json: bytes) -> bytes:
    """gzip at rest. ``mtime=0`` keeps the bytes deterministic for one input."""
    return gzip.compress(body_json, compresslevel=6, mtime=0)


async def current(db: AsyncSession, server: DNSServer) -> DNSAgentBundle | None:
    """The stored bundle at the server's watermark, metadata only (the body
    column is deferred), or ``None`` when nothing current is stored."""
    if server.bundle_watermark is None or not is_current(server):
        return None
    return (
        await db.execute(
            select(DNSAgentBundle).where(
                DNSAgentBundle.server_id == server.id,
                DNSAgentBundle.dirty_watermark == server.bundle_watermark,
            )
        )
    ).scalar_one_or_none()


async def load_body(db: AsyncSession, bundle: DNSAgentBundle) -> bytes:
    """The gzip bytes of one stored bundle — read only when answering 200."""
    return (
        await db.execute(select(DNSAgentBundle.body).where(DNSAgentBundle.id == bundle.id))
    ).scalar_one()


async def store(
    db: AsyncSession,
    server: DNSServer,
    *,
    dirty_watermark: int,
    snapshot_at: datetime,
    etag: str,
    structural_etag: str,
    ships_ops: bool,
    body_json: bytes,
    records: int,
    render_ms: int,
    rendered_by: str,
) -> DNSAgentBundle | None:
    """Insert one rendered bundle and mirror it onto the server row.

    Returns ``None`` — and writes nothing — when a row for
    ``(server, dirty_watermark)`` already exists: a concurrent render (two
    api replicas building inline, or the api racing the worker during the
    migration release) simply lost, and the caller serves the row that
    won. The mirror columns only ever move forward, so a slow render that
    finishes after a newer one cannot roll the served bundle back. The
    render counter is incremented in SQL so it is exact under that race.
    """
    body_gz = compress_body(body_json)
    inserted = (
        await db.execute(
            pg_insert(DNSAgentBundle)
            .values(
                id=uuid.uuid4(),
                server_id=server.id,
                dirty_watermark=dirty_watermark,
                snapshot_at=snapshot_at,
                etag=etag,
                structural_etag=structural_etag,
                ships_ops=ships_ops,
                body=body_gz,
                body_bytes=len(body_json),
                body_gzip_bytes=len(body_gz),
                records=records,
                render_ms=render_ms,
                rendered_by=rendered_by,
            )
            .on_conflict_do_nothing(constraint="uq_dns_agent_bundle_server_watermark")
            .returning(DNSAgentBundle.id, DNSAgentBundle.built_at)
        )
    ).one_or_none()
    if inserted is None:
        logger.info(
            "dns_agent_bundle_already_stored",
            server_id=str(server.id),
            watermark=dirty_watermark,
            rendered_by=rendered_by,
        )
        return None
    new_id, built_at = inserted

    await db.execute(
        update(DNSServer)
        .where(DNSServer.id == server.id)
        .values(
            bundle_render_count=DNSServer.bundle_render_count + 1,
            bundle_render_status=RENDER_STATUS_OK,
            bundle_render_error=None,
            bundle_render_at=func.now(),
        )
    )
    await db.execute(
        update(DNSServer)
        .where(
            DNSServer.id == server.id,
            or_(
                DNSServer.bundle_watermark.is_(None),
                DNSServer.bundle_watermark <= dirty_watermark,
            ),
        )
        .values(
            bundle_watermark=dirty_watermark,
            bundle_etag=etag,
            bundle_built_at=built_at,
            bundle_rendered_by=rendered_by,
        )
    )
    await prune(db, server.id)
    # The caller's instance must see what SQL just wrote (expire_on_commit is
    # False everywhere, so nothing else would reload it).
    await db.refresh(server)
    logger.info(
        "dns_agent_bundle_stored",
        server_id=str(server.id),
        watermark=dirty_watermark,
        etag=etag,
        structural_etag=structural_etag,
        records=records,
        body_bytes=len(body_json),
        body_gzip_bytes=len(body_gz),
        render_ms=render_ms,
        rendered_by=rendered_by,
    )
    row = await db.get(DNSAgentBundle, new_id)
    assert row is not None  # just inserted in this transaction
    return row


async def prune(db: AsyncSession, server_id: uuid.UUID) -> int:
    """Keep the newest ``dns_agent_bundle_keep_versions`` rows per server."""
    keep = max(1, int(settings.dns_agent_bundle_keep_versions))
    keepers = (
        select(DNSAgentBundle.id)
        .where(DNSAgentBundle.server_id == server_id)
        .order_by(DNSAgentBundle.dirty_watermark.desc())
        .limit(keep)
    )
    result = await db.execute(
        delete(DNSAgentBundle).where(
            DNSAgentBundle.server_id == server_id,
            DNSAgentBundle.id.not_in(keepers),
        )
    )
    return int(result.rowcount or 0)


async def record_failure(db: AsyncSession, server: DNSServer, error: str) -> None:
    """A render that raised is visible on the server row, never served."""
    text = (error or "").strip()[:_MAX_ERROR] or "render failed"
    await db.execute(
        update(DNSServer)
        .where(DNSServer.id == server.id)
        .values(
            bundle_render_status=RENDER_STATUS_FAILED,
            bundle_render_error=text,
            bundle_render_at=func.now(),
        )
    )
    logger.warning("dns_agent_bundle_render_failed", server_id=str(server.id), error=text)


__all__ = [
    "DYNAMIC_KEYS",
    "RENDERED_BY_API",
    "RENDERED_BY_WORKER",
    "RENDER_STATUS_FAILED",
    "RENDER_STATUS_OK",
    "compress_body",
    "current",
    "encode_body",
    "is_current",
    "load_body",
    "prune",
    "record_failure",
    "store",
]
