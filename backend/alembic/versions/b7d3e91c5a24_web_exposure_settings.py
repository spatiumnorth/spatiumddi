"""platform_settings.web_exposure: the reachability / exposure detection config (#3651)

One JSONB column holds the whole configuration of the ``security.web_exposure``
module (trusted networks, the "intentional" acknowledgement, the evaluation
window and threshold, and the opt-in mitigation switches), validated by
``app.services.web_exposure.config.WebExposureConfig``. An empty object is the
shipped default: detection watches only once the module is turned on, and every
mitigation is off.

The module row is deliberately NOT seeded (CLAUDE.md non-negotiable #14).

Revision ID: b7d3e91c5a24
Revises: b6d2e9f41a07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b7d3e91c5a24"
down_revision: str | None = "b6d2e9f41a07"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "platform_settings",
        sa.Column(
            "web_exposure",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("platform_settings", "web_exposure")
