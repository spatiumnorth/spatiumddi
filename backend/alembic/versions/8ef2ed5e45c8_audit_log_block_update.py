"""audit_log: refuse UPDATE with a BEFORE UPDATE trigger (#2315)

``audit_log`` was guarded against DELETE only (``audit_log_no_delete``,
#73), so an UPDATE that rewrote a row went through and the "append-only"
conformity policy said nothing. This adds ``audit_log_no_update``, a
``BEFORE UPDATE … FOR EACH ROW`` trigger whose function raises.

Nothing in the application updates ``audit_log``: rows are only ever
inserted, a restore reloads them with COPY, and no foreign key points a
``SET NULL`` into the table. The two earlier migrations that rewrote the
hash chain (``d92f4a18c763``, ``d4f8c91a2e35``) run before this one; a
future migration that has to rewrite rows must disable this trigger for
the duration and re-enable it.

TRUNCATE is deliberately not guarded: the per-test truncation and the
selective restore of the ``audit`` section both TRUNCATE the table.

Revision ID: 8ef2ed5e45c8
Revises: e7b3d19a4c26
Create Date: 2026-10-23 10:00:00.000000
"""

from alembic import op

revision = "8ef2ed5e45c8"
down_revision = "e7b3d19a4c26"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_log_block_update()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only: UPDATE refused (issue #2315)';
        END;
        $$ LANGUAGE plpgsql;
        """)
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
    op.execute(
        "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION audit_log_block_update()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_block_update()")
