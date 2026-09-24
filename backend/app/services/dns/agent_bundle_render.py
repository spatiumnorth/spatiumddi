"""Render one DNS agent bundle and store it (#1111).

Shared by the worker task (``app.tasks.agent_bundles``) and, during the
migration release, by the api's inline fallback in the long-poll. Both
run the same build ``build_config_bundle`` always ran — minus the ops
page — serialise it once in the #958 wire shape and hand the bytes to
``agent_bundle_store``.

Ordering inside is load-bearing:

1. read ``bundle_dirty_seq`` — the watermark this render will claim;
2. take ``snapshot_at`` and the transaction snapshot, in one statement —
   the gate on which queued ops this body covers;
3. read everything else.

A change that commits after step 1 leaves the sequence ahead of the
watermark, so the stored bundle is stale by its own accounting and gets
re-rendered; a change that commits before step 1 is visible to every read
in step 3. Reading the sequence LAST would let a bundle claim a sequence
whose change it never read — stale served as current, the one failure
this design exists to rule out.

Step 2 must stay its own statement before step 3. Under READ COMMITTED
every statement takes a fresh snapshot, so the records query sees at least
every transaction visible in step 2's: an op whose transaction is visible
there has its record in the body. That, not ``created_at`` (the op's
transaction START), is what the ops page and the split-horizon retire gate
on (``agent_config._covered_by``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from sqlalchemy import Text, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSAgentBundle, DNSServer
from app.services.dns import agent_bundle_store as bundle_store
from app.services.dns.agent_config import render_bundle_body, retire_queued_ops


@dataclass(frozen=True)
class RenderOutcome:
    """What one render did. ``bundle`` is ``None`` when another render had
    already stored this watermark (the store is idempotent on it)."""

    bundle: DNSAgentBundle | None
    watermark: int
    etag: str
    structural_etag: str
    records: int
    render_ms: int
    body_bytes: int
    rendered_by: str

    @property
    def stored(self) -> bool:
        return self.bundle is not None


async def render_and_store(
    db: AsyncSession, server: DNSServer, *, rendered_by: str
) -> RenderOutcome:
    """Render ``server``'s bundle at its current dirty sequence and store it.

    The caller owns the transaction: commit after this returns (the worker
    does; the api fallback commits with its ``last_config_etag`` write).
    Under split-horizon the queued ops the render folded in are retired
    here too — only those committed before the render read, so an op that
    landed mid-render is never retired unseen.
    """
    started = time.monotonic()
    await db.refresh(server)
    watermark = int(server.bundle_dirty_seq)
    # Its own statement, before the records are read (module docstring).
    snapshot_at, visible_xacts = (
        await db.execute(select(func.clock_timestamp(), cast(func.pg_current_snapshot(), Text)))
    ).one()
    rendered = await render_bundle_body(db, server)
    body_json = bundle_store.encode_body(rendered.body)
    render_ms = int((time.monotonic() - started) * 1000)
    # Exactly the inline build's rule: under split-horizon the queued ops the
    # render folded in are retired — unless the server is in maintenance,
    # where nothing moves until the operator resumes (#182).
    if rendered.has_views and not server.maintenance_mode:
        await retire_queued_ops(db, server, up_to=snapshot_at, visible_xacts=visible_xacts)
    row = await bundle_store.store(
        db,
        server,
        dirty_watermark=watermark,
        snapshot_at=snapshot_at,
        visible_xacts=visible_xacts,
        etag=rendered.etag,
        structural_etag=rendered.structural_etag,
        ships_ops=not rendered.has_views,
        body_json=body_json,
        records=rendered.records,
        render_ms=render_ms,
        rendered_by=rendered_by,
    )
    return RenderOutcome(
        bundle=row,
        watermark=watermark,
        etag=rendered.etag,
        structural_etag=rendered.structural_etag,
        records=rendered.records,
        render_ms=render_ms,
        body_bytes=len(body_json),
        rendered_by=rendered_by,
    )


__all__ = ["RenderOutcome", "render_and_store"]
