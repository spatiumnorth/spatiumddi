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
    before it was migrated. A row whose value an operator has since edited
    (an ``update`` audit row naming ``value``) keeps its ``import_source`` but
    is NOT the importer's value any more: it is left as typed, or, in a
    Technitium group, takes rule (a).

The rewrite has to reach the agents, and a raw UPDATE is invisible to the
``bundle_dirty`` listener, so the migration also does what an API edit does:

* bumps ``bundle_dirty_seq`` on every agent-based server of each group it
  rewrote, so no stored bundle of theirs is current;
* rewrites the same targets in those servers' queued (``pending`` /
  ``in_flight``) record ops, whose ``record`` payload was snapshotted from the
  old value, both ``value`` (matched to its row by ``record_id``) and
  ``rrset.members[].value``;
* for (b) rows in a BIND9 / PowerDNS group, queues a whole-RRset ``update``
  op per agent server and bumps the zone serial. Records are not structural
  there (#1373), so the bump alone never reaches the daemon: without the op
  the row would say ``web.example.net.`` while the daemon kept serving
  ``web.example.net.<zone>.``. A Technitium group needs none, because its
  marker (below) is structural and re-reconciles every record.

Agentless groups other than ``technitium_api`` (Windows DNS, the cloud
providers) get the row rewrite and no push: a migration cannot call a
driver. Their next write to the name, or Sync with Servers, converges it.

What keeps a replay of a cached pre-#1759 bundle from being re-read under the
new rule is not here: it is the ``name_target_rule`` marker the renderer
(``RENDERER_REVISION`` 7) puts in a Technitium server's bundle, absent from an
old one, so the agent reads that bundle's dot-less targets as absolute.

Revision ID: d6b2f81a3c57
Revises: e3a81c5d07f2
Create Date: 2026-10-11
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime

import sqlalchemy as sa

from alembic import op

revision = "d6b2f81a3c57"
down_revision = "e3a81c5d07f2"
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
    # A quoted token is a NAPTR regexp, not a replacement: a NAPTR written
    # without its replacement must not get a dot glued onto its regexp.
    if target in ("", ".", "@") or target.endswith(".") or target.startswith('"'):
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


def _rewrite_op(
    record: dict,
    group_id,
    technitium: bool,
    imported_ids: set,
    other_ids: set,
    imported: dict,
) -> dict | None:
    """The op payload with its value and RRset members rewritten, or None
    when nothing in it changes.

    The op's own value is matched to its row by ``record_id`` (#1230), which
    every op built by ``record_op_payload`` carries: a row classified as
    Technitium-imported gets the every-label rule applied to the op's OWN
    value (an older op may hold an older value than the row), any other row
    the multi-label rule in a Technitium group. RRset members carry no id, so
    they, and an op without ``record_id``, fall back to the row content
    ``(zone, name, type, old value)``.
    """
    rtype = str(record.get("type") or "").upper()
    if rtype not in _TYPES:
        return None
    zone = record.get("_zone_name")
    key = _op_key(group_id, zone, record.get("name"), rtype)
    rid = record.get("record_id")
    rid = str(rid) if rid is not None else None

    def by_content(v):
        # (b): a row imported from Technitium held this value.
        if (key, v) in imported:
            return imported[(key, v)]
        # (a): multi-label dot-less, in a Technitium group.
        return _dot_terminate(rtype, v, single_label=False) if technitium else v

    def own(v):
        if not isinstance(v, str):
            return v
        if rid in imported_ids:
            return _dot_terminate(rtype, v, single_label=True)
        if rid in other_ids:
            return _dot_terminate(rtype, v, single_label=False) if technitium else v
        return by_content(v)

    changed = False
    out = dict(record)
    out.pop("_zone_name", None)
    if isinstance(out.get("value"), str):
        new = own(out["value"])
        changed |= new != out["value"]
        out["value"] = new
    rrset = out.get("rrset")
    if isinstance(rrset, dict) and isinstance(rrset.get("members"), list):
        members = []
        for m in rrset["members"]:
            if isinstance(m, dict) and isinstance(m.get("value"), str):
                new = by_content(m["value"])
                changed |= new != m["value"]
                m = {**m, "value": new}
            members.append(m)
        out["rrset"] = {**rrset, "members": members}
    return out if changed else None


def _same_rr(a: dict, b: dict) -> bool:
    """``services/dns/rrset._same_rr``: value plus the structured fields."""
    if str(a.get("value") or "").strip() != str(b.get("value") or "").strip():
        return False
    return all(a.get(f) == b.get(f) for f in ("priority", "weight", "port"))


def _next_serial(current: int, now: datetime) -> int:
    """``services/dns/serial.compute_next_serial``, frozen here so a later
    change to it cannot change what this migration did."""
    today = int(now.strftime("%Y%m%d")) * 100
    if 1_000_000_000 <= current <= 9_999_999_999:
        if current // 100 == today // 100:
            return current + 1
        return today if today > current else current + 1
    return today if today > current else current + 1


def _push_rewritten_rrsets(conn, rewritten: dict) -> set:
    """Queue a whole-RRset ``update`` op for every RRset of a NON-Technitium
    group whose member this migration re-pointed, on each enabled agent
    server of the group, as ``enqueue_record_ops_batch`` would. Returns the
    groups it queued for.

    In a group without views a record only reaches a BIND9 / PowerDNS daemon
    as a record op (#1373: records are not structural, so neither the
    ``bundle_dirty_seq`` bump nor a re-render rewrites the zone on the
    wire). Without these ops the row would read ``web.example.net.`` while
    the daemon kept serving ``web.example.net.<zone>.``. A Technitium group
    needs none: the ``name_target_rule`` marker is structural, so its arrival
    re-reconciles every record of every zone.

    ``rewritten`` maps ``(zone_id, lower(name), type)`` to one rewritten row id.
    """
    if not rewritten:
        return set()
    zone_ids = sorted({k[0] for k in rewritten}, key=str)
    zones = {
        z.id: z
        for z in conn.execute(
            sa.text("""
                SELECT id, name, group_id, ttl, last_serial FROM dns_zone
                WHERE id = ANY(:ids) AND deleted_at IS NULL
                ORDER BY id FOR NO KEY UPDATE
                """),
            {"ids": zone_ids},
        ).fetchall()
    }
    servers: dict = {}
    for sid, gid in conn.execute(
        sa.text("""
            SELECT id, group_id FROM dns_server
            WHERE group_id = ANY(:g) AND is_enabled
              AND driver IN ('technitium', 'bind9', 'powerdns')
            ORDER BY is_primary DESC, created_at
            """),
        {"g": sorted({z.group_id for z in zones.values()}, key=str)},
    ).fetchall():
        servers.setdefault(gid, []).append(sid)

    now = datetime.now(UTC)
    serials: dict = {}
    queued: set = set()
    for (zone_id, lname, rtype), row_id in sorted(rewritten.items(), key=str):
        zone = zones.get(zone_id)
        targets = servers.get(zone.group_id) if zone is not None else None
        if not targets:
            continue
        rows = conn.execute(
            sa.text("""
                SELECT id, name, value, ttl, priority, weight, port FROM dns_record
                WHERE zone_id = :z AND lower(name) = :n AND record_type = :t
                  AND deleted_at IS NULL
                ORDER BY created_at, id
                """),
            {"z": zone_id, "n": lname, "t": rtype},
        ).fetchall()
        own = next((r for r in rows if r.id == row_id), None)
        if own is None:
            continue
        default_ttl = 3600 if zone.ttl is None else zone.ttl
        members: list = []
        for r in rows:
            m = {"value": r.value}
            for f in ("priority", "weight", "port"):
                if getattr(r, f) is not None:
                    m[f] = getattr(r, f)
            if not any(_same_rr(m, kept) for kept in members):
                members.append(m)
        ttls = [default_ttl if r.ttl is None else r.ttl for r in rows]
        if zone_id not in serials:
            serials[zone_id] = _next_serial(int(zone.last_serial or 0), now)
        record = {
            "record_id": str(own.id),
            "name": own.name,
            "type": rtype,
            "value": own.value,
            "ttl": own.ttl,
            "priority": own.priority,
            "weight": own.weight,
            "port": own.port,
            "rrset": {"ttl": min(ttls) if ttls else default_ttl, "members": members},
        }
        for sid in targets:
            conn.execute(
                sa.text("""
                    INSERT INTO dns_record_op
                        (id, server_id, zone_name, op, record, target_serial, state, attempts)
                    VALUES (:id, :s, :z, 'update', CAST(:r AS jsonb), :serial, 'pending', 0)
                    """),
                {
                    "id": uuid.uuid4(),
                    "s": sid,
                    "z": zone.name,
                    "r": json.dumps(record),
                    "serial": serials[zone_id],
                },
            )
        queued.add(zone.group_id)
    for zone_id, serial in serials.items():
        conn.execute(
            sa.text("UPDATE dns_zone SET last_serial = :s WHERE id = :id"),
            {"s": serial, "id": zone_id},
        )
    return queued


def upgrade() -> None:
    conn = op.get_bind()
    touched: set = set()
    # (group, zone, name, type, old value) -> new value, for the imported rows:
    # an RRset member does not name its record, so it is matched on content.
    imported: dict = {}
    # Row ids whose op payloads take the every-label rule, and every other row
    # this migration looked at (an op naming one takes the multi-label rule).
    imported_ids: set = set()
    other_ids: set = set()
    # Re-pointed RRsets of non-Technitium groups, which need a wire push.
    rewritten: dict = {}

    rows = conn.execute(sa.text(f"""
            SELECT r.id, r.name, r.record_type, r.value, r.import_source,
                   r.zone_id, z.name, z.group_id,
                   z.group_id IN ({_TECHNITIUM_GROUPS}) AS technitium,
                   r.deleted_at IS NULL AND z.deleted_at IS NULL AS live,
                   EXISTS (
                       SELECT 1 FROM audit_log a
                       WHERE a.resource_type = 'dns_record'
                         AND a.resource_id = r.id::text
                         AND a.action = 'update'
                         AND a.changed_fields @> '["value"]'::jsonb
                   ) AS edited
            FROM dns_record r
            JOIN dns_zone z ON z.id = r.zone_id
            WHERE r.record_type IN ({_TYPE_LIST})
              AND (r.import_source = 'technitium'
                   OR z.group_id IN ({_TECHNITIUM_GROUPS}))
            """)).fetchall()
    for (
        rid,
        name,
        rtype,
        value,
        import_source,
        zone_id,
        zone_name,
        group_id,
        technitium,
        live,
        edited,
    ) in rows:
        # A value an operator has since edited is theirs, not the importer's:
        # it means what they typed under the reading their group gives it.
        is_imported = import_source == "technitium" and not edited
        if not is_imported and not technitium:
            continue
        (imported_ids if is_imported else other_ids).add(str(rid))
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
        if not technitium and live:
            rewritten.setdefault((zone_id, (name or "@").lower(), rtype.upper()), rid)

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
            {**record, "_zone_name": zone_name},
            group_id,
            technitium,
            imported_ids,
            other_ids,
            imported,
        )
        if new_record is not None:
            conn.execute(
                sa.text("UPDATE dns_record_op SET record = CAST(:r AS jsonb) WHERE id = :id"),
                {"r": json.dumps(new_record), "id": oid},
            )
            touched.add(group_id)

    # After the queued ops are rewritten, so the new ones are not rewritten
    # again, and queued last, so they supersede the older ones.
    touched |= _push_rewritten_rrsets(conn, rewritten)

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
