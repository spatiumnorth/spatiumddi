"""dns_zone.agentless_create_due_at — an auto-created zone not yet at its provider (#1932)

IPAM create, auto-sync, DDNS and subnet create auto-create a subnet's reverse
zone. In a group with agentless servers (technitium_api, Windows Path B, the
cloud drivers) only the zone endpoints ever pushed a zone to the provider, so
those reverse zones existed in SpatiumDDI alone and every PTR op for them
failed "no such zone". The column marks a zone whose provider create is still
outstanding; the value is when the agentless retry sweep may next try. NULL
means nothing is outstanding.

Backfill: the reverse zones SpatiumDDI auto-created in a group that has an
agentless server with credentials are exactly the zones that bug left behind,
so they are marked due now and the sweep creates them after the upgrade. A
zone that is already at the provider (made by hand meanwhile) is found there
and adopted or left as it is; nothing is deleted. Imported zones are not
marked: they came from a provider.

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

# Frozen copy of ``app.drivers.dns.AGENTLESS_DRIVERS`` at this revision.
_AGENTLESS_DRIVERS = (
    "windows_dns",
    "technitium_api",
    "cloudflare",
    "route53",
    "azure_dns",
    "google_dns",
    "digitalocean",
    "hetzner",
    "linode",
    "vultr",
)


def upgrade() -> None:
    op.add_column(
        "dns_zone",
        sa.Column("agentless_create_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(sa.text("""
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
                      AND s.driver IN ({drivers})
               )
            """.format(drivers=", ".join(f"'{d}'" for d in _AGENTLESS_DRIVERS))))


def downgrade() -> None:
    op.drop_column("dns_zone", "agentless_create_due_at")
