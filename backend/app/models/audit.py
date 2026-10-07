import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, Sequence, String, Text, func
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    """
    Append-only audit trail of all data mutations.
    Stored in PostgreSQL (not the log store) for queryability and compliance.
    No application-layer deletes are ever performed on this table.
    A DB-level trigger prevents DELETE as an extra guard (issue #73).

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

    # result: success | denied | error
    result: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tamper-evidence chain (issue #73). Set by the runtime hasher;
    # ``prev_hash`` is NULL only on the very first row.
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
