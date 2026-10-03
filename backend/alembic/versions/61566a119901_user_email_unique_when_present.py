"""user.email is unique only when there is one (#1290).

``ix_user_email`` was a plain unique index, and an external account with no
email is created with ``email = ''``. RADIUS and TACACS+ never report an
email, and neither does an LDAP entry without ``mail`` or an OIDC token
without the claim, so on such a provider exactly one account could ever be
auto-provisioned: every later first-time login violated the index and
failed.

The index becomes partial, ``WHERE email <> ''``: real emails stay unique,
and any number of accounts can have none. Same name, so the model's
``Index("ix_user_email", ...)`` and this migration agree.

No data change: the old index allowed at most one empty email, which the new
one keeps.

DOWNGRADE
---------
Restores the plain unique index. That fails if more than one account has an
empty email, which this release makes possible, so the downgrade checks first
and refuses with a clear message rather than a bare unique violation. Give
those accounts distinct emails (or remove them) before downgrading.

Revision ID: 61566a119901
Revises: 5e6d56b39ab7
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "61566a119901"
down_revision = "5e6d56b39ab7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_user_email", table_name="user")
    op.create_index(
        "ix_user_email",
        "user",
        ["email"],
        unique=True,
        postgresql_where=sa.text("email <> ''"),
    )


def downgrade() -> None:
    empty = (
        op.get_bind().execute(sa.text("SELECT count(*) FROM \"user\" WHERE email = ''")).scalar()
    )
    if empty and empty > 1:
        raise RuntimeError(
            f"{empty} accounts have an empty email, and the plain unique index on "
            "user.email that this downgrade restores allows at most one. Give them "
            "distinct emails, or remove them, before downgrading (#1290)."
        )
    op.drop_index("ix_user_email", table_name="user")
    op.create_index("ix_user_email", "user", ["email"], unique=True)
