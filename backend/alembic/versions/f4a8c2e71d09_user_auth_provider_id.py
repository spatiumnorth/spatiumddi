"""User.auth_provider_id: external accounts belong to a provider, not a type (#1235).

External logins were matched on ``(auth_source, external_id)``, where
``auth_source`` is the provider TYPE (``ldap``, ``oidc``, ...). With two
providers of one type, the second could sign in as the first one's users.
This adds the provider reference the match is now keyed on.

Backfill, best effort and never guessing:

* RADIUS / TACACS+ accounts carry their provider in the external id
  (``<provider id>:<username>``), so they are attributed exactly.
* An LDAP / OIDC / SAML account is attributed when exactly one provider of
  its type exists AND the account cannot have come from any other: it was
  created after that provider was, and after the last deletion of any other
  provider of its type. Released builds left a deleted provider's accounts in
  place (auth_source + external_id intact), so "one provider of the type
  exists now" did not mean "only one ever did". An earlier draft of this
  backfill handed an account of a provider deleted before the upgrade to the
  survivor, and the survivor's subject with the same identifier signed in as
  it (found by QA on #1289). The deletes are read from ``audit_log``; the delete row carries
  no type, so it is joined to the provider's ``create`` row, which has
  recorded ``new_value.type`` since auth providers shipped. A delete whose
  type cannot be recovered counts as every type: it only ever withholds a
  link, never grants one. And the survivor's own ``create`` row must be
  there: an audit log missing it (restored without its section) cannot show
  that nothing was deleted either, so nothing is attributed.
* A RADIUS / TACACS+ account whose prefix names no existing provider is left
  NULL rather than given to the survivor.

Everything left NULL is refused at its next sign-in with
``account_link_required`` until an administrator links it
(``POST /users/{id}/link-provider``).

A plain index rather than a unique one: an install that already holds two
rows with one provider and one external id must still be able to upgrade.

Revision ID: f4a8c2e71d09
Revises: d8e1b5a26c47
Create Date: 2026-09-29
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "f4a8c2e71d09"
down_revision = "d8e1b5a26c47"
branch_labels = None
depends_on = None


# RADIUS / TACACS+: the provider id is the external id's prefix.
BACKFILL_BY_PREFIX = """
    UPDATE "user" u
       SET auth_provider_id = p.id
      FROM auth_provider p
     WHERE u.auth_provider_id IS NULL
       AND u.auth_source IN ('radius', 'tacacs')
       AND p.type = u.auth_source
       AND u.external_id LIKE p.id::text || ':%'
"""

# Every other external type: only when exactly one provider of the type
# exists and the account cannot have come from another one (see the module
# docstring). RADIUS / TACACS+ are excluded: their external id names the
# provider, so one the prefix pass did not attribute came from a provider
# that no longer exists, and the sole survivor is exactly the guess this
# backfill refuses to make.
BACKFILL_SOLE_PROVIDER = """
    UPDATE "user" u
       SET auth_provider_id = p.id
      FROM auth_provider p
     WHERE u.auth_provider_id IS NULL
       AND u.auth_source NOT IN ('local', 'radius', 'tacacs')
       AND u.external_id IS NOT NULL
       AND p.type = u.auth_source
       AND (SELECT count(*) FROM auth_provider q WHERE q.type = u.auth_source) = 1
       -- The audit log covers the survivor's lifetime: every provider is
       -- created through the API, which writes this row. Without it (a
       -- restore that left the audit log out) the deletions below are
       -- unknown too, so nothing is attributed.
       AND EXISTS (
           SELECT 1
             FROM audit_log c
            WHERE c.action = 'create'
              AND c.resource_type = 'auth_provider'
              AND c.resource_id = p.id::text
       )
       -- The account postdates the survivor, so it was not made before it.
       AND u.created_at >= p.created_at
       -- No other provider that may have been of this type was deleted after
       -- the account was made, so that provider cannot have made it.
       AND NOT EXISTS (
           SELECT 1
             FROM audit_log d
            WHERE d.action = 'delete'
              AND d.resource_type = 'auth_provider'
              AND d.resource_id <> p.id::text
              AND d.timestamp > u.created_at
              AND COALESCE(
                      (SELECT c.new_value ->> 'type'
                         FROM audit_log c
                        WHERE c.action = 'create'
                          AND c.resource_type = 'auth_provider'
                          AND c.resource_id = d.resource_id
                        LIMIT 1),
                      u.auth_source
                  ) = u.auth_source
       )
"""


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column("auth_provider_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_user_auth_provider_id_auth_provider",
        "user",
        "auth_provider",
        ["auth_provider_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_user_auth_provider_id", "user", ["auth_provider_id"])

    op.execute(BACKFILL_BY_PREFIX)
    op.execute(BACKFILL_SOLE_PROVIDER)


def downgrade() -> None:
    op.drop_index("ix_user_auth_provider_id", table_name="user")
    op.drop_constraint("fk_user_auth_provider_id_auth_provider", "user", type_="foreignkey")
    op.drop_column("user", "auth_provider_id")
