"""Technitium name-valued targets: write the trailing dot they were served with (#1759).

Until #1759 both Technitium paths (the agent and the agentless
``technitium_api`` driver) stripped the dot off a CNAME / DNAME / NS / PTR /
MX / SRV / NAPTR-replacement target and sent the rest as-is, and Technitium
has no relative names, so a stored ``www CNAME web.example.net`` was served
as ``web.example.net.``. The #744 importer and the Sync-with-Servers pull
wrote exactly that shape, without the dot, for every record they read off a
Technitium daemon.

#1759 makes those paths read a target the way a zone file does (no trailing
dot means relative to the zone, ``@`` is the zone), so the same stored value
would now be sent as ``web.example.net.<zone>``: every such record re-pointed
on upgrade. This migration writes the dot those records were already served
with, so nothing served changes. Same shape as ``a3d9e5c17b42`` (#1513), which
did this for SVCB / HTTPS only.

Two sets of rows, with different intent:

(a) Every multi-label dot-less target in a group running a Technitium driver
    (``technitium`` / ``technitium_api``). A single label (``web``) is left
    alone: it was served as the TLD-shaped ``web.``, which nothing means, and
    #1759 now serves it as ``web.<zone>.``; that is the fix. ``@`` and ``.``
    are left alone for the same reason (``@`` was refused outright; ``.`` was
    sent empty and refused).

(b) Every row the Technitium importer / pull stamped
    (``import_source = 'technitium'``), in ANY group, single labels and
    all. Technitium reports an absolute name with no dot, so the intent of
    those values was always absolute. In a BIND9 / PowerDNS group a dot-less
    value is relative to the zone, so such a row is served as
    ``target.<zone>.`` today, which is wrong. Adding the dot **deliberately
    changes what those groups serve** to the name the Technitium zone served
    before it was migrated. A row an operator has since edited by hand keeps
    its ``import_source`` and is rewritten too; that is the one place this
    can be wrong, and it errs toward the value's origin.

The rewrite has to reach the agents, and a raw UPDATE is invisible to the
``bundle_dirty`` listener, so the migration also does what an API edit does:

* bumps ``bundle_dirty_seq`` on every agent-based server of each group it
  rewrote, so no stored bundle of theirs is current;
* rewrites the same targets in those servers' queued (``pending`` /
  ``in_flight``) record ops, whose ``record`` payload was snapshotted from the
  old value, both ``value`` and ``rrset.members[].value``.

What keeps a replay of a cached pre-#1759 bundle from being re-read under the
new rule is not here: it is the ``name_target_rule`` marker the renderer
(``RENDERER_REVISION`` 7) puts in a Technitium server's bundle, absent from an
old one, so the agent reads that bundle's dot-less targets as absolute.

Revision ID: d6b2f81a3c57
Revises: a3d9e5c17b42
Create Date: 2026-10-11
"""

from __future__ import annotations

import json
import re

import sqlalchemy as sa

from alembic import op

revision = "d6b2f81a3c57"
down_revision = "a3d9e5c17b42"
branch_labels = None
depends_on = None

# The whole value is the target.
_PLAIN = ("CNAME", "DNAME", "NS", "PTR", "MX", "SRV")
# ``order pref "flags" "services" "regexp" replacement``: the target is the
# last whitespace-separated token.
_NAPTR = re.compile(r"^(.*\s)(\S+)(\s*)$", re.S)
_TYPES = _PLAIN + ("NAPTR",)
_TYPE_LIST = ", ".join(f"'{t}'" for t in _TYPES)


def _dot_terminate(rtype: str, value: str, *, single_label: bool) -> str:
    """``value`` with its target made absolute, or unchanged when it already
    is, is ``@`` / ``.``, or (unless ``single_label``) has only one label."""
    if not isinstance(value, str):
        return value
    if (rtype or "").upper() == "NAPTR":
        m = _NAPTR.match(value)
        if not m:
            return value
        head, target, tail = m.groups()
        fixed = _fix_target(target, single_label)
        return value if fixed == target else f"{head}{fixed}{tail}"
    stripped = value.strip()
    fixed = _fix_target(stripped, single_label)
    return value if fixed == stripped else fixed


def _fix_target(target: str, single_label: bool) -> str:
    if target in ("", ".", "@") or target.endswith("."):
        return target
    if "." not in target and not single_label:
        return target
    return f"{target}."


_TECHNITIUM_GROUPS = """
    SELECT DISTINCT s.group_id FROM dns_server s
    WHERE s.driver IN ('technitium', 'technitium_api')
"""


def _op_key(group_id, zone_name, name, rtype):
    return (
        str(group_id),
        (zone_name or "").rstrip(".").lower(),
        (name or "@").lower() or "@",
        (rtype or "").upper(),
    )


def _rewrite_op(record: dict, group_id, technitium: bool, imported: dict) -> dict | None:
    """The op payload with its value and RRset members rewritten, or None
    when nothing in it changes."""
    rtype = str(record.get("type") or "").upper()
    if rtype not in _TYPES:
        return None
    zone = record.get("_zone_name")
    key = _op_key(group_id, zone, record.get("name"), rtype)

    def fix(v):
        if not isinstance(v, str):
            return v
        # (b): the row this value belongs to was imported from Technitium.
        if (key, v) in imported:
            return imported[(key, v)]
        # (a): multi-label dot-less, in a Technitium group.
        return _dot_terminate(rtype, v, single_label=False) if technitium else v

    changed = False
    out = dict(record)
    out.pop("_zone_name", None)
    if isinstance(out.get("value"), str):
        new = fix(out["value"])
        changed |= new != out["value"]
        out["value"] = new
    rrset = out.get("rrset")
    if isinstance(rrset, dict) and isinstance(rrset.get("members"), list):
        members = []
        for m in rrset["members"]:
            if isinstance(m, dict) and isinstance(m.get("value"), str):
                new = fix(m["value"])
                changed |= new != m["value"]
                m = {**m, "value": new}
            members.append(m)
        out["rrset"] = {**rrset, "members": members}
    return out if changed else None


def upgrade() -> None:
    conn = op.get_bind()
    touched: set = set()
    # (group, zone, name, type, old value) -> new value, for the imported rows:
    # a queued op does not name its record, so it is matched on content.
    imported: dict = {}

    rows = conn.execute(sa.text(f"""
            SELECT r.id, r.name, r.record_type, r.value, r.import_source,
                   z.name, z.group_id,
                   z.group_id IN ({_TECHNITIUM_GROUPS}) AS technitium
            FROM dns_record r
            JOIN dns_zone z ON z.id = r.zone_id
            WHERE r.record_type IN ({_TYPE_LIST})
              AND (r.import_source = 'technitium'
                   OR z.group_id IN ({_TECHNITIUM_GROUPS}))
            """)).fetchall()
    for rid, name, rtype, value, import_source, zone_name, group_id, technitium in rows:
        is_imported = import_source == "technitium"
        new = _dot_terminate(rtype, value, single_label=is_imported)
        if new == value:
            continue
        conn.execute(
            sa.text("UPDATE dns_record SET value = :v WHERE id = :id"),
            {"v": new, "id": rid},
        )
        touched.add(group_id)
        if is_imported:
            imported[(_op_key(group_id, zone_name, name, rtype), value)] = new

    ops = conn.execute(
        sa.text(
            """
            SELECT o.id, o.record, o.zone_name, s.group_id,
                   s.group_id IN ("""
            + _TECHNITIUM_GROUPS
            + """) AS technitium
            FROM dns_record_op o
            JOIN dns_server s ON s.id = o.server_id
            WHERE o.state IN ('pending', 'in_flight')
            """
        )
    ).fetchall()
    for oid, record, zone_name, group_id, technitium in ops:
        if isinstance(record, str):
            record = json.loads(record)
        if not isinstance(record, dict):
            continue
        new_record = _rewrite_op(
            {**record, "_zone_name": zone_name}, group_id, technitium, imported
        )
        if new_record is not None:
            conn.execute(
                sa.text("UPDATE dns_record_op SET record = CAST(:r AS jsonb) WHERE id = :id"),
                {"r": json.dumps(new_record), "id": oid},
            )
            touched.add(group_id)

    if touched:
        # What ``bundle_dirty._bump`` does at commit: agent-based servers only
        # (the agentless drivers have no bundle), locked in server-id order the
        # way every marker takes them.
        conn.execute(
            sa.text("""
                UPDATE dns_server
                SET bundle_dirty_seq = bundle_dirty_seq + 1,
                    bundle_dirty_at = COALESCE(bundle_dirty_at, now())
                WHERE id IN (
                    SELECT id FROM dns_server
                    WHERE group_id = ANY(:groups)
                      AND driver IN ('technitium', 'bind9', 'powerdns')
                    ORDER BY id FOR NO KEY UPDATE
                )
                """),
            {"groups": list(touched)},
        )


def downgrade() -> None:
    # The added dot is correct under either reading (an absolute name is
    # absolute whether or not the old code would have added the dot), so
    # there is nothing to undo; and which rows were rewritten is not
    # recorded, so it could not be undone selectively anyway.
    pass
