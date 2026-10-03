"""audit_log.auth_source and user_session.auth_source hold a whole provider name (#1337).

Every external sign-in writes the provider's NAME into both columns: the
session row (the session viewer's "signed in via ...", #72), and the audit
log's login row plus every error and refusal row on the way
(``api/v1/auth/router.py``: the password fallthrough, the OIDC and SAML
callbacks). A provider name may be 255 characters (``auth_provider.name``),
but the columns were VARCHAR(64) and VARCHAR(20). So a sign-in through a
provider named over 20 characters failed its insert
(StringDataRightTruncation): the login answered 422 "A supplied value cannot
be stored as sent.", and the session, the audit row and ``last_login_at``
rolled back with it. An unreachable provider with such a name also stopped
the fallthrough to the providers after it, because its error row failed the
same way.

Both columns are widened to 255, the width of the name they carry.

* Widening a varchar is a catalogue-only change in PostgreSQL: no table
  rewrite and no index rebuild (neither column is indexed), so it is quick on
  a large ``audit_log``.
* It is safe for the previous release during a rolling upgrade, which only
  ever writes values that fit the old widths.

Downgrade narrows them back. PostgreSQL refuses that ("value too long") while
any row holds a longer value; it does not truncate. That is the intent: an
audit row's content is covered by its ``row_hash`` (#73), so it must never be
rewritten, and audit rows are never deleted.

Revision ID: cd10b699d988
Revises: b3c71e9a4d25
Create Date: 2026-10-02
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "cd10b699d988"
down_revision = "b3c71e9a4d25"
branch_labels = None
depends_on = None

# The width of ``auth_provider.name``: every value these columns receive is a
# provider name or one of the short fixed sources (``local``, ``system``, ...).
_NAME = 255


def upgrade() -> None:
    op.alter_column(
        "audit_log",
        "auth_source",
        existing_type=sa.String(length=20),
        type_=sa.String(length=_NAME),
        existing_nullable=False,
    )
    op.alter_column(
        "user_session",
        "auth_source",
        existing_type=sa.String(length=64),
        type_=sa.String(length=_NAME),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "user_session",
        "auth_source",
        existing_type=sa.String(length=_NAME),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
    op.alter_column(
        "audit_log",
        "auth_source",
        existing_type=sa.String(length=_NAME),
        type_=sa.String(length=20),
        existing_nullable=False,
    )
