import uuid
from datetime import datetime

from sqlalchemy import (
    DDL,
    BigInteger,
    DateTime,
    Index,
    Integer,
    Sequence,
    String,
    Text,
    event,
    func,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    """
    Append-only audit trail of all data mutations.
    Stored in PostgreSQL (not the log store) for queryability and compliance.
    No application-layer deletes or updates are ever performed on this
    table. DB-level triggers refuse DELETE (issue #73) and UPDATE (issue
    #2315) as an extra guard; see ``AUDIT_LOG_GUARD_TRIGGERS``. They make
    the table tamper-evident, not tamper-proof: the table owner can drop
    them, which the ``audit_log_immutable`` conformity check reports.

    ``seq`` + ``row_hash`` + ``prev_hash`` form a tamper-evident chain
    (issue #73). The hash is computed in
    ``app.services.audit_chain.compute_audit_hashes`` via a SQLAlchemy
    ``before_flush`` event listener — every new audit row goes through
    that path, which takes a Postgres advisory lock to serialise the
    "look up the previous row, hash, append" sequence so concurrent
    inserts can't interleave and break the chain.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_timestamp", "timestamp"),
        Index("ix_audit_log_user_id", "user_id"),
        Index("ix_audit_log_resource", "resource_type", "resource_id"),
        Index("ix_audit_log_action", "action"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Ordered position in the chain. Auto-assigned via ``audit_log_seq_seq``
    # in the migration; the runtime hasher selects the row with
    # ``seq = MAX(seq)`` to fetch ``prev_hash`` so the chain is contiguous
    # even when two rows share a timestamp. ``server_default`` tells the
    # ORM to omit the column on INSERT so Postgres picks the next value
    # from the sequence.
    # ``Sequence("audit_log_seq_seq")`` is declared here so that
    # ``Base.metadata.create_all`` (used by the test suite) creates the
    # sequence alongside the table — without it, asyncpg raises
    # ``UndefinedTableError: relation "audit_log_seq_seq" does not exist``
    # the first time a row is inserted. Production still goes through
    # the Alembic migration ``d92f4a18c763_audit_chain_hash`` which
    # creates the same sequence; SQLAlchemy's ``CREATE SEQUENCE IF NOT
    # EXISTS`` semantics + Alembic's idempotency keep the two paths in
    # sync.
    seq: Mapped[int] = mapped_column(
        BigInteger,
        Sequence("audit_log_seq_seq"),
        nullable=False,
        server_default=sa_text("nextval('audit_log_seq_seq')"),
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Who
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    user_display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # auth_source: ``local``, a fixed service source (``system``, ``acme``, ...),
    # or the NAME of the provider an external sign-in went through, so it is as
    # wide as ``auth_provider.name`` (#1337: it was 20, and a longer provider
    # name broke every sign-in through that provider).
    auth_source: Mapped[str] = mapped_column(String(255), nullable=False, default="local")
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # What
    # action: create | update | delete | login | logout | sync | permission_change | ...
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_display: Mapped[str] = mapped_column(String(500), nullable=False)

    # State change
    old_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    changed_fields: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    # Correlation
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # result: success | denied | error | failure (a rejected sign-in, #1836)
    result: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tamper-evidence chain (issue #73). Set by the runtime hasher;
    # ``prev_hash`` is NULL only on the very first row.
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


# The row triggers that make ``audit_log`` append-only: trigger name ->
# (the event it refuses, the function it runs). Production creates them in
# the Alembic migrations ``d92f4a18c763`` (DELETE, #73) and ``8ef2ed5e45c8``
# (UPDATE, #2315); the ``after_create`` hooks below create the same objects
# under ``Base.metadata.create_all``, which is what the test suite uses, so
# tests run against the guarded table. The ``audit_log_immutable``
# conformity check reads this mapping to know what must be present.
# TRUNCATE is deliberately not guarded: the test suite and the selective
# restore of the ``audit`` section both truncate the table.
AUDIT_LOG_GUARD_TRIGGERS: dict[str, tuple[str, str]] = {
    "audit_log_no_delete": ("DELETE", "audit_log_block_delete"),
    "audit_log_no_update": ("UPDATE", "audit_log_block_update"),
}

_GUARD_MESSAGES = {
    "audit_log_block_delete": "audit_log is append-only (issue #73)",
    "audit_log_block_update": "audit_log is append-only: UPDATE refused (issue #2315)",
}

for _trigger, (_event, _function) in AUDIT_LOG_GUARD_TRIGGERS.items():
    event.listen(
        AuditLog.__table__,
        "after_create",
        DDL(
            f"CREATE OR REPLACE FUNCTION {_function}() RETURNS TRIGGER AS $$ "
            f"BEGIN RAISE EXCEPTION '{_GUARD_MESSAGES[_function]}'; END; "
            "$$ LANGUAGE plpgsql"
        ),
    )
    event.listen(
        AuditLog.__table__,
        "after_create",
        DDL(
            f"CREATE TRIGGER {_trigger} BEFORE {_event} ON audit_log "
            f"FOR EACH ROW EXECUTE FUNCTION {_function}()"
        ),
    )


class AuditChainCheckpoint(Base):
    """Singleton: how far the nightly verifier has walked the chain (#2286).

    ``verified_seq`` / ``verified_hash`` name the last row verified clean in
    a walk that began at the first row, so the next run starts after it
    instead of re-reading the table. ``full_pass_done_at`` is when that walk
    first reached the end of the table; the verifier discards the checkpoint
    a week later and walks everything again. The verifier re-checks that the
    row still carries ``verified_hash`` before trusting it, so a stale
    checkpoint (restore, rewritten row) costs a full pass, never a false
    "verified".
    """

    __tablename__ = "audit_chain_checkpoint"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    verified_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    verified_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    full_pass_done_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
