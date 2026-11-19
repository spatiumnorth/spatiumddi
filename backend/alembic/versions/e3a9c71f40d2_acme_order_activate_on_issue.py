"""#3067 — ``acme_order.activate_on_issue``: issue without taking over the Web UI.

A successful fresh ACME issue made the new certificate the sole active
(Web UI) certificate, deploying it to nginx. With the certificate store on
its own permission, a caller holding ``certificate_store`` but not
``admin`` on ``appliance`` issues a DoT / DoH / DoQ certificate with
``activate: false``; the worker reads this column to know not to activate
it.

NOT NULL with ``server_default true``: every existing order was placed under
the old behaviour, which activated, so ``true`` is what those rows did rather
than a guess.

Revision ID: e3a9c71f40d2
Revises: c4f81e2a9d37
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "e3a9c71f40d2"
down_revision: str | None = "c4f81e2a9d37"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "acme_order",
        sa.Column(
            "activate_on_issue",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )


def downgrade() -> None:
    op.drop_column("acme_order", "activate_on_issue")
