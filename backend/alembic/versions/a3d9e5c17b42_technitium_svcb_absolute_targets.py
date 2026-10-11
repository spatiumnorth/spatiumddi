"""Technitium SVCB / HTTPS targets: write the trailing dot they were served with (#1513).

Until #1513 both Technitium paths (the agent and the agentless
``technitium_api`` driver) stripped the dot off an SVCB / HTTPS target and
sent the rest as-is, and Technitium has no relative names — so a stored
``1 cdn.example.net alpn=h2`` was served as ``cdn.example.net.``. The #744
importer and the Sync-with-Servers pull wrote exactly that shape, without
the dot, for every record they read off a Technitium daemon.

#1513 makes those paths read a target the way a zone file does — no
trailing dot means relative to the zone — so the same stored value would
now be sent as ``cdn.example.net.<zone>``: every such record re-pointed on
upgrade. This migration writes the dot those records were already served
with, so nothing served changes.

Only multi-label targets, and only in groups running a Technitium driver.
A single label (``svc``) is left alone: it was served as the TLD-shaped
``svc.``, which nothing means, and #1513 now serves it as ``svc.<zone>.`` —
the fix, not something to preserve. BIND9 / PowerDNS groups always read a
dot-less target as relative, so their records mean today what they meant
before.

The rewrite has to reach the agents, and a raw UPDATE is invisible to the
``bundle_dirty`` listener (``services/dns/bundle_dirty.py``: a Core write must
mark itself), so the migration also does what an API edit does:

* bumps ``bundle_dirty_seq`` on every server of each group it rewrote, so no
  stored bundle of theirs is current and the next one carries the new value;
* rewrites the same targets in those servers' queued (``pending`` /
  ``in_flight``) record ops, whose ``record`` payload was snapshotted from the
  old value and would otherwise ship it under the new reading.

What makes an agent re-reconcile, and what keeps a replay of a cached
pre-#1513 bundle from being re-read under the new rule, is not here: both are
the ``svcb_target_rule`` marker the renderer (``RENDERER_REVISION`` 6) puts in
a Technitium server's bundle — in its structural fingerprint, so its arrival
re-reconciles every Technitium agent once, and absent from an old bundle, so
the agent reads that bundle's dot-less targets as absolute, as they were meant.

Revision ID: a3d9e5c17b42
Revises: c2f7a94e1d58
Create Date: 2026-10-09
"""

from __future__ import annotations

import json
import re

import sqlalchemy as sa

from alembic import op

revision = "a3d9e5c17b42"
down_revision = "c2f7a94e1d58"
branch_labels = None
depends_on = None

# priority, whitespace, target, then the params verbatim.
_VALUE = re.compile(r"^(\s*\S+\s+)(\S+)(.*)$", re.S)


def _dot_terminate(value: str) -> str:
    m = _VALUE.match(value or "")
    if not m:
        return value
    head, target, rest = m.groups()
    if target in (".", "@") or target.endswith(".") or "." not in target:
        return value
    return f"{head}{target}.{rest}"


_TECHNITIUM_GROUPS = """
    SELECT DISTINCT s.group_id FROM dns_server s
    WHERE s.driver IN ('technitium', 'technitium_api')
"""


def _dot_terminate_op(record: dict) -> dict | None:
    """The op payload with its value and RRset members rewritten, or None
    when nothing in it changes."""
    if str(record.get("type") or "").upper() not in ("SVCB", "HTTPS"):
        return None
    changed = False
    out = dict(record)
    if isinstance(out.get("value"), str):
        new = _dot_terminate(out["value"])
        changed |= new != out["value"]
        out["value"] = new
    rrset = out.get("rrset")
    if isinstance(rrset, dict) and isinstance(rrset.get("members"), list):
        members = []
        for m in rrset["members"]:
            if isinstance(m, dict) and isinstance(m.get("value"), str):
                new = _dot_terminate(m["value"])
                changed |= new != m["value"]
                m = {**m, "value": new}
            members.append(m)
        out["rrset"] = {**rrset, "members": members}
    return out if changed else None


def upgrade() -> None:
    conn = op.get_bind()
    rows = conn.execute(sa.text(f"""
            SELECT r.id, r.value, z.group_id
            FROM dns_record r
            JOIN dns_zone z ON z.id = r.zone_id
            WHERE r.record_type IN ('SVCB', 'HTTPS')
              AND z.group_id IN ({_TECHNITIUM_GROUPS})
            """)).fetchall()
    touched: set = set()
    for rid, value, group_id in rows:
        new = _dot_terminate(value)
        if new != value:
            conn.execute(
                sa.text("UPDATE dns_record SET value = :v WHERE id = :id"),
                {"v": new, "id": rid},
            )
            touched.add(group_id)

    ops = conn.execute(sa.text(f"""
            SELECT o.id, o.record, s.group_id
            FROM dns_record_op o
            JOIN dns_server s ON s.id = o.server_id
            WHERE o.state IN ('pending', 'in_flight')
              AND s.group_id IN ({_TECHNITIUM_GROUPS})
            """)).fetchall()
    for oid, record, group_id in ops:
        if isinstance(record, str):
            record = json.loads(record)
        if not isinstance(record, dict):
            continue
        new_record = _dot_terminate_op(record)
        if new_record is not None:
            conn.execute(
                sa.text("UPDATE dns_record_op SET record = CAST(:r AS jsonb) WHERE id = :id"),
                {"r": json.dumps(new_record), "id": oid},
            )
            touched.add(group_id)

    if touched:
        # What ``bundle_dirty._bump`` does at commit: agent-based servers only
        # (``technitium_api`` is agentless and has no bundle), locked in
        # server-id order the way every marker takes them.
        conn.execute(
            sa.text("""
                UPDATE dns_server
                SET bundle_dirty_seq = bundle_dirty_seq + 1,
                    bundle_dirty_at = COALESCE(bundle_dirty_at, now())
                WHERE id IN (
                    SELECT id FROM dns_server
                    WHERE group_id = ANY(:groups) AND driver = 'technitium'
                    ORDER BY id FOR NO KEY UPDATE
                )
                """),
            {"groups": list(touched)},
        )


def downgrade() -> None:
    # The added dot is correct under either reading (an absolute name is
    # absolute whether or not the old code would have added the dot), so
    # there is nothing to undo.
    pass
