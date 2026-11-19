"""dns_zone.agentless_create_due_at + dns_server_group.auto_reverse_zones_at_provider (#1932)

IPAM create, auto-sync, DDNS and subnet create auto-create a subnet's reverse
zone. In a group with agentless servers (technitium_api, Windows Path B, the
cloud drivers) only the zone endpoints ever pushed a zone to the provider, so
those reverse zones existed in SpatiumDDI alone and every PTR op for them
failed "no such zone".

``dns_zone.agentless_create_due_at`` marks a zone whose provider create is
still outstanding; the value is when the agentless retry sweep may next try.
NULL means nothing is outstanding.

``dns_server_group.auto_reverse_zones_at_provider`` (NOT NULL, default false)
is the opt-in for auto-creating reverse zones in a group running a cloud DNS
driver, which bills per hosted zone. Every existing group starts opted out;
groups on other drivers ignore it.

Backfill: the reverse zones SpatiumDDI auto-created in a group with a
technitium_api or Windows DNS server with credentials, and no cloud server,
are exactly the zones the bug left behind, so they are marked due now and the
sweep creates them after the upgrade. A zone already at the provider (made by
hand meanwhile) is found there and adopted or left as it is. Cloud groups are
not marked, since they start opted out: reverse zone rows they already hold
are left as they are, and nothing is created at a cloud provider by the
upgrade. Imported zones are not marked: they came from a provider. Nothing
is deleted.

Revision ID: c4f19a2e7d53
Revises: a1903c5e7b24
Create Date: 2026-10-15

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "c4f19a2e7d53"
down_revision = "a1903c5e7b24"
branch_labels = None
depends_on = None

# Frozen copies, at this revision, of the agentless drivers that are not
# cloud drivers, and of ``app.drivers.dns.CLOUD_DNS_DRIVERS``.
_NON_CLOUD_AGENTLESS = ("windows_dns", "technitium_api")
_CLOUD_DRIVERS = (
    "cloudflare",
    "route53",
    "azure_dns",
    "google_dns",
    "digitalocean",
    "hetzner",
    "linode",
    "vultr",
)


def _in_list(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.add_column(
        "dns_zone",
        sa.Column("agentless_create_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "dns_server_group",
        sa.Column(
            "auto_reverse_zones_at_provider",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.execute(sa.text(f"""
            UPDATE dns_zone AS z
               SET agentless_create_due_at = now()
             WHERE z.is_auto_generated
               AND z.kind = 'reverse'
               AND z.deleted_at IS NULL
               AND z.import_source IS NULL
               AND EXISTS (
                   SELECT 1 FROM dns_server AS s
                    WHERE s.group_id = z.group_id
                      AND s.credentials_encrypted IS NOT NULL
                      AND s.driver IN ({_in_list(_NON_CLOUD_AGENTLESS)})
               )
               AND NOT EXISTS (
                   SELECT 1 FROM dns_server AS c
                    WHERE c.group_id = z.group_id
                      AND c.driver IN ({_in_list(_CLOUD_DRIVERS)})
               )
            """))


def downgrade() -> None:
    op.drop_column("dns_server_group", "auto_reverse_zones_at_provider")
    op.drop_column("dns_zone", "agentless_create_due_at")
