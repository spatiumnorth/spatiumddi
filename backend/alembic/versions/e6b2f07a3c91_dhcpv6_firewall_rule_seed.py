"""DHCPv6 server port for the dhcp role — builtin firewall rule seed (#1139).

Adds one rule to the existing ``dhcp`` builtin policy seeded by
f5b8d2c91a06: ``udp/547`` accepted from anywhere.

The ``dhcp`` role opened UDP 67 / 68 only, so on an appliance serving an
IPv6 scope every DHCPv6 packet reached the NIC and died on the ``input``
chain's drop policy: on-link Solicits to ``ff02::1:2`` and — the reported
case — a relay's Relay-Forward sent to the server's unicast address, both on
547. Kea's v6 server has no raw-socket mode (v4's LPF sockets see packets
before netfilter, which is why DHCPv4 never needed the firewall's help), so
the rule is the only way in. Replies (Advertise / Reply to 546, Relay-Reply
to the relay's 547) are outbound, and ``output`` accepts everything.

Always open rather than gated on "an IPv6 scope exists": kea-dhcp6 runs on
every dhcp node whether or not it has v6 subnets, nothing in the role
assignment carries scope families, and the policy model cannot express the
condition. An idle kea-dhcp6 answers nothing on the port.

seq 20 follows the v4 rule (10). The merged renderer emits each role port as
its own line in sorted order regardless of seq, so the output stays byte-
identical to the two hardcoded renderers, which carry 547 in their
``_ROLE_PORTS_UDP`` tables.

Idempotent: ``ON CONFLICT (policy_id, seq) DO NOTHING``, same as the parent
seed, so an operator who already added 547 by hand at another seq keeps a
harmless duplicate the merge unions away. ``backend/tests/
test_firewall_merge.py::test_builtin_seed_matches_migration`` keeps this in
lock-step with ``_BUILTIN_SEED`` in ``app/services/appliance/firewall_merge.py``.

Revision ID: e6b2f07a3c91
Revises: b7d21c9e4f06
Create Date: 2026-09-24
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision: str = "e6b2f07a3c91"
down_revision: str | None = "b7d21c9e4f06"
branch_labels: str | None = None
depends_on: str | None = None

_SCOPE_ROLE = "dhcp"
_RULES: list = [
    (20, "accept", "udp", [547], "any", "both", None, None),
]
# Same (scope_kind, scope_role, name, enabled, rules) shape as
# f5b8d2c91a06's ``_POLICIES``; name None because this adds a RULE to a
# policy that already exists (see d4a9e37b2c15 for why upgrade / downgrade
# iterate this structure rather than ``_RULES``).
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
    # Only the rule THIS migration added — the dhcp policy and the v4 rule
    # f5b8d2c91a06 seeded into it must survive.
    for _scope_kind, scope_role, _name, _enabled, rules in _POLICIES:
        for seq, *_rest in rules:
            op.execute(
                sa.text(
                    "DELETE FROM firewall_rule WHERE seq = :seq AND policy_id IN "
                    "(SELECT id FROM firewall_policy WHERE scope_kind = 'role' "
                    " AND scope_role = :sr AND is_builtin)"
                ).bindparams(sr=scope_role, seq=seq)
            )
