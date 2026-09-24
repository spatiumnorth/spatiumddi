"""Looking-glass role — builtin firewall policy seed (#1166).

Adds the ``looking-glass`` role policy: ``tcp/179`` accepted from anywhere,
so a router can initiate the BGP session with a passive collector (#566).

The three appliance firewall renderers are meant to be byte-identical, and
only the supervisor's in-pod renderer carried 179 for this role. The backend
renderer's port table had no entry and no builtin policy existed, so the
moment fleet firewall enforcement was switched on — and the merged renderer
drove the node — a looking-glass node dropped every inbound BGP connection.
Sessions the collector dials out were unaffected, which is why it went
unnoticed; the identity test's matrix had no looking-glass case to catch it.

Same shape as 6a668dd451d5 (the Technitium policy), in its own migration per
the append-only rule. Idempotent: NOT EXISTS / ON CONFLICT DO NOTHING.
``backend/tests/test_firewall_merge.py::test_builtin_seed_matches_migration``
keeps this in lock-step with ``_BUILTIN_SEED``.

Revision ID: b8e2d5c07a14
Revises: f4c8a2d61b37
Create Date: 2026-09-24
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision: str = "b8e2d5c07a14"
down_revision: str | None = "f4c8a2d61b37"
branch_labels: str | None = None
depends_on: str | None = None

_SCOPE_ROLE = "looking-glass"
_NAME = "Looking Glass (BGP)"
_RULES: list = [
    (10, "accept", "tcp", [179], "any", "both", None, None),
]
# Same (scope_kind, scope_role, name, enabled, rules) shape as
# f5b8d2c91a06's ``_POLICIES`` — test_builtin_seed_matches_migration
# concatenates every seed migration's ``_POLICIES`` list uniformly.
_POLICIES: list = [("role", _SCOPE_ROLE, _NAME, True, _RULES)]


def upgrade() -> None:
    for _scope_kind, scope_role, name, _enabled, rules in _POLICIES:
        op.execute(
            sa.text(
                "INSERT INTO firewall_policy "
                "(id, name, description, scope_kind, scope_role, enabled, is_builtin, priority, "
                " created_at, modified_at) "
                "SELECT gen_random_uuid(), :name, NULL, 'role', :sr, true, true, 100, now(), now() "
                "WHERE NOT EXISTS "
                "(SELECT 1 FROM firewall_policy WHERE scope_kind = 'role' AND scope_role = :sr)"
            ).bindparams(name=name, sr=scope_role)
        )
        for seq, action, proto, ports, skind, fam, comment, guard in rules:
            op.execute(
                sa.text(
                    "INSERT INTO firewall_rule "
                    "(id, policy_id, seq, action, protocol, ports, source_kind, source_cidrs, "
                    " source_alias, family, comment, render_guard, enabled) "
                    "SELECT gen_random_uuid(), p.id, :seq, :action, :proto, "
                    " CAST(:ports AS jsonb), :skind, '[]'::jsonb, NULL, :fam, :comment, "
                    " CAST(:guard AS jsonb), true "
                    "FROM firewall_policy p WHERE p.scope_kind = 'role' AND p.scope_role = :sr "
                    "ON CONFLICT (policy_id, seq) DO NOTHING"
                ).bindparams(
                    sr=scope_role,
                    seq=seq,
                    action=action,
                    proto=proto,
                    ports=json.dumps(ports),
                    skind=skind,
                    fam=fam,
                    comment=comment,
                    guard=json.dumps(guard) if guard is not None else None,
                )
            )


def downgrade() -> None:
    for _scope_kind, scope_role, _name, _enabled, _rules in _POLICIES:
        op.execute(
            sa.text(
                "DELETE FROM firewall_rule WHERE policy_id IN "
                "(SELECT id FROM firewall_policy WHERE scope_kind = 'role' "
                " AND scope_role = :sr AND is_builtin)"
            ).bindparams(sr=scope_role)
        )
        op.execute(
            sa.text(
                "DELETE FROM firewall_policy WHERE scope_kind = 'role' AND scope_role = :sr "
                "AND is_builtin"
            ).bindparams(sr=scope_role)
        )
