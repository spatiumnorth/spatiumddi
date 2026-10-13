"""DNS allow_recursion: the default becomes local + private networks (#1817).

``dns_server_options.allow_recursion`` defaulted to ``["any"]``, and the BIND9
agent always renders ``allow-query { any; }``. An unset ``allow-recursion``
inherits ``allow-query`` (BIND 9.20 ``server.c``), so a recursive group on
default settings answered recursive queries for the whole internet. #1786
made the value render but kept ``["any"]`` unrendered to avoid changing
behaviour; the maintainer's decision on #1817 is that the default is local
+ private networks (``localhost; localnets; 10.0.0.0/8; 172.16.0.0/12;
192.168.0.0/16; fc00::/7; fe80::/10;``) and every value renders literally.
``localnets`` alone is not enough: it is the subnets of the interfaces named
sees, which is the LAN only where BIND shares the host's network (the plain
appliance). Behind the appliance DNS VIP, in the umbrella chart, the raw k8s
manifests and Compose, BIND runs on a pod / bridge network, so ``localnets``
is that network and the private ranges are what keep a LAN recursing.

This migration:

* rewrites every row whose list is exactly ``["any"]`` (case and whitespace
  ignored), plus an empty list or JSON null, which meant "the default", to
  that list. Any other list is an operator's choice and
  is untouched, as is an explicit ``any`` mixed with other elements;
* changes the column ``server_default`` to the new default;
* bumps ``bundle_dirty_seq`` on every agent-based server of each rewritten
  group, so no stored bundle of theirs is current and agents re-render.

UPGRADE NOTE: a recursive group whose clients use public addresses (routed
public subnets, globally routable IPv6 on a pod-network shape) or CGNAT /
Tailscale addresses (``100.64.0.0/10`` is deliberately not in the default)
loses recursion until those networks are added to ``allow_recursion``;
``any`` restores fully open recursion.

The downgrade rewrites exactly the new default list back to ``["any"]``. A group an operator deliberately set to that list is
indistinguishable and is rewritten too; that is the old default's behaviour.

Revision ID: b8e41c7a2d95
Revises: d6b2f81a3c57
Create Date: 2026-10-12
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "b8e41c7a2d95"
down_revision = "d6b2f81a3c57"
branch_labels = None
depends_on = None

_NEW = [
    "localhost",
    "localnets",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10",
]
_OLD = ["any"]


def _norm(value: object) -> list[str] | None:
    """The list lower-cased and stripped, or None when it is not a list."""
    if not isinstance(value, list):
        return None
    return [str(e).strip().lower() for e in value if str(e).strip()]


def _rewrite(match, new: list[str]) -> None:
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, group_id, allow_recursion FROM dns_server_options"))
    ids: list = []
    groups: list = []
    for row_id, group_id, value in rows.fetchall():
        if match(value):
            ids.append(row_id)
            groups.append(group_id)
    if not ids:
        return
    conn.execute(
        sa.text(
            "UPDATE dns_server_options SET allow_recursion = CAST(:v AS jsonb) "
            "WHERE id = ANY(:ids)"
        ),
        {"v": json.dumps(new), "ids": ids},
    )
    # What ``bundle_dirty._bump`` does at commit: agent-based servers only,
    # locked in server-id order the way every marker takes them.
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
        {"groups": groups},
    )


def _was_default(value: object) -> bool:
    # None / [] meant "the default" (the agent rendered nothing for them).
    return value is None or _norm(value) in ([], ["any"])


def upgrade() -> None:
    _rewrite(_was_default, _NEW)
    op.alter_column(
        "dns_server_options",
        "allow_recursion",
        server_default=sa.text(f"'{json.dumps(_NEW)}'::jsonb"),
    )


def downgrade() -> None:
    op.alter_column(
        "dns_server_options",
        "allow_recursion",
        server_default=sa.text("""'["any"]'::jsonb"""),
    )
    _rewrite(lambda v: _norm(v) == _NEW, _OLD)
