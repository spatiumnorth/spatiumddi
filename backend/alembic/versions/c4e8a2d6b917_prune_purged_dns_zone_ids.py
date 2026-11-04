"""Clear DNS zone ids that name a zone which no longer exists (#3443).

IPAM spaces, blocks, subnets, subnet templates and addresses store the zone
they publish into as text (``dns_zone_id``) or a JSONB id list
(``dns_additional_zone_ids``, ``ip_address.extra_zone_ids``) with no foreign
key, and purging a zone never cleared the id. The purge paths now prune it;
this removes the ids already stranded, and the ones in a not-yet-applied
subnet plan's tree.

A zone in the Trash is still a zone (a restore brings it back), so an id is
dead only when no ``dns_zone`` row has it. Ids are compared by their hex
digits (any spelling ``uuid.UUID`` reads) and the order of the entries kept is
preserved. Data-only; the downgrade is a
no-op (the removed ids named nothing).

Revision ID: c4e8a2d6b917
Revises: b3d7e19a5c40
"""

from __future__ import annotations

import json
import uuid

import sqlalchemy as sa

from alembic import op

revision: str = "c4e8a2d6b917"
down_revision: str | None = "b3d7e19a5c40"
branch_labels: str | None = None
depends_on: str | None = None


def _norm(expr: str) -> str:
    # The 32 hex digits, whatever the spelling: before #2923 an id was stored
    # as given, and the readers parse it with ``uuid.UUID``, which takes
    # upper case, braces, no hyphens and ``urn:uuid:``. A plain text compare
    # would clear such an id although it names a live zone.
    return f"regexp_replace(lower({expr}), 'urn:|uuid:|[{{}}-]', '', 'g')"


_LIVE = "(SELECT replace(id::text, '-', '') FROM dns_zone)"


def upgrade() -> None:
    for table in ("ip_space", "ip_block", "subnet", "ipam_template"):
        op.execute(f"""
            UPDATE {table} SET dns_zone_id = NULL
            WHERE dns_zone_id IS NOT NULL AND dns_zone_id <> ''
              AND {_norm("dns_zone_id")} NOT IN {_LIVE}
            """)
    for table, col in (
        ("ip_space", "dns_additional_zone_ids"),
        ("ip_block", "dns_additional_zone_ids"),
        ("subnet", "dns_additional_zone_ids"),
        ("ipam_template", "dns_additional_zone_ids"),
        ("ip_address", "extra_zone_ids"),
    ):
        op.execute(f"""
            UPDATE {table} SET {col} = COALESCE((
                SELECT jsonb_agg(e ORDER BY o)
                FROM jsonb_array_elements({col}) WITH ORDINALITY AS t(e, o)
                WHERE {_norm("e #>> '{}'")} IN {_LIVE}
            ), '[]'::jsonb)
            WHERE jsonb_typeof({col}) = 'array'
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements({col}) x
                WHERE {_norm("x #>> '{}'")} NOT IN {_LIVE}
              )
            """)

    # Plan trees are nested JSON; walk them in Python. Applied plans are a
    # record of what was created and are left as they are.
    bind = op.get_bind()
    live = {str(r[0]) for r in bind.execute(sa.text("SELECT id FROM dns_zone"))}
    rows = bind.execute(sa.text("SELECT id, tree FROM subnet_plan WHERE applied_at IS NULL"))
    for plan_id, tree in rows.fetchall():
        if isinstance(tree, str):
            tree = json.loads(tree)
        if _strip_dead(tree, live):
            bind.execute(
                sa.text("UPDATE subnet_plan SET tree = CAST(:t AS jsonb) WHERE id = :i"),
                {"t": json.dumps(tree), "i": plan_id},
            )


def _strip_dead(node: object, live: set[str]) -> bool:
    if not isinstance(node, dict):
        return False
    changed = False
    zid = node.get("dns_zone_id")
    if zid:
        try:
            key = str(uuid.UUID(str(zid)))
        except ValueError:
            key = ""
        if key not in live:
            node["dns_zone_id"] = None
            changed = True
    for child in node.get("children") or []:
        changed = _strip_dead(child, live) or changed
    return changed


def downgrade() -> None:
    pass
