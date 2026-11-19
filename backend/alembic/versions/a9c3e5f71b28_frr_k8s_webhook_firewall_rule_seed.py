"""frr-k8s's webhook between control-plane peers — builtin firewall rule seed (#1827).

Adds one rule to the existing ``control-plane`` builtin policy seeded by
f5b8d2c91a06: ``tcp/19443`` accepted from the cluster peers, under the same
guard as the MetalLB memberlist rules (multi-node + a control-plane VIP).

In BGP mode MetalLB delegates to frr-k8s, whose validating webhook for
``FRRConfiguration`` objects is served by the ``frr-k8s-statuscleaner`` pod
with ``hostNetwork: true`` on port 19443 — on ONE node. Every other node's
apiserver calls it at that node's own address, so the call crosses that
node's ``input`` chain, which is ``policy drop`` and opened nothing on 19443.
The webhook fails closed, and each speaker's write of its node's
``FRRConfiguration`` goes to whichever apiserver the kubernetes Service
picks: only the writes that landed on the webhook's own node passed, and the
other nodes never got a BGP configuration (0 to 2 of 3 on a three-node
cluster) while the settings reported every speaker ready.

``cluster_peers`` and the memberlist guard, not a BGP flag: the supervisor
does not mirror the MetalLB settings, MetalLB is only ever enabled with a
control-plane VIP, and on a single node the webhook call stays on loopback.

seq 50 places it after the memberlist rules (30/40), matching where both
hardcoded renderers emit it — the byte-identity contract across the three
renderers is on the ORDER, not just the set.

Idempotent: ``ON CONFLICT (policy_id, seq) DO NOTHING``, same as the parent
seed. ``backend/tests/test_firewall_merge.py::
test_builtin_seed_matches_migration`` keeps this in lock-step with
``_BUILTIN_SEED`` in ``app/services/appliance/firewall_merge.py``.

Revision ID: a9c3e5f71b28
Revises: d2a6e81f3b57
Create Date: 2026-10-16
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision: str = "a9c3e5f71b28"
down_revision: str | None = "d2a6e81f3b57"
branch_labels: str | None = None
depends_on: str | None = None

_SCOPE_ROLE = "control-plane"
# The memberlist rules' guard, verbatim (f5b8d2c91a06's ``_GUARD``);
# test_builtin_seed_matches_migration asserts it equals ``_BUILTIN_GUARD``.
_GUARD: dict = {"min_cp_members": 2, "requires_vip": True}
_RULES: list = [
    (50, "accept", "tcp", [19443], "cluster_peers", "both", "frr-k8s-webhook", _GUARD),
]
# Same (scope_kind, scope_role, name, enabled, rules) shape as
# f5b8d2c91a06's ``_POLICIES``; the name is None because this migration adds
# a RULE to a policy that already exists (d4a9e37b2c15's shape).
# ``upgrade`` / ``downgrade`` iterate THIS, so the structure the drift test
# asserts on is the one the migration executes.
_POLICIES: list = [("role", _SCOPE_ROLE, None, True, _RULES)]


def upgrade() -> None:
    for _scope_kind, scope_role, _name, _enabled, rules in _POLICIES:
        for seq, action, proto, ports, skind, fam, comment, guard in rules:
            _insert_rule(scope_role, seq, action, proto, ports, skind, fam, comment, guard)


def _insert_rule(  # noqa: PLR0913 — mirrors the seed tuple's shape
    scope_role: str,
    seq: int,
    action: str,
    proto: str,
    ports: list,
    skind: str,
    fam: str,
    comment: str | None,
    guard: dict | None,
) -> None:
    op.execute(
        sa.text(
            "INSERT INTO firewall_rule "
            "(id, policy_id, seq, action, protocol, ports, source_kind, source_cidrs, "
            " source_alias, family, comment, render_guard, enabled) "
            "SELECT gen_random_uuid(), p.id, :seq, :action, :proto, CAST(:ports AS jsonb), "
            " :skind, '[]'::jsonb, NULL, :fam, :comment, CAST(:guard AS jsonb), true "
            "FROM firewall_policy p WHERE p.scope_kind = 'role' AND p.scope_role = :sr "
            " AND p.is_builtin "
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
    # Only the rule THIS migration added — the control-plane policy and the
    # rules earlier seeds put in it must survive.
    for _scope_kind, scope_role, _name, _enabled, rules in _POLICIES:
        for seq, *_rest in rules:
            op.execute(
                sa.text(
                    "DELETE FROM firewall_rule WHERE seq = :seq AND policy_id IN "
                    "(SELECT id FROM firewall_policy WHERE scope_kind = 'role' "
                    " AND scope_role = :sr AND is_builtin)"
                ).bindparams(sr=scope_role, seq=seq)
            )
