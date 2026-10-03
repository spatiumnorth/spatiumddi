import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
)
from sqlalchemy import (
    text as sa_text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.time_bound_grant import TimeBoundGrant

# Many-to-many: users ↔ groups
user_group = Table(
    "user_group",
    Base.metadata,
    Column(
        "user_id", UUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "group_id", UUID(as_uuid=True), ForeignKey("group.id", ondelete="CASCADE"), primary_key=True
    ),
)

# Many-to-many: groups ↔ roles
group_role = Table(
    "group_role",
    Base.metadata,
    Column(
        "group_id", UUID(as_uuid=True), ForeignKey("group.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "role_id", UUID(as_uuid=True), ForeignKey("role.id", ondelete="CASCADE"), primary_key=True
    ),
)


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "user"

    # ``_active_time_bound_grants`` below is a plain per-request attribute,
    # not a mapped column. ``__allow_unmapped__`` tells SQLAlchemy 2.0's
    # declarative scanner to leave non-``Mapped[...]`` annotations alone
    # instead of raising ``ArgumentError`` for them.
    __allow_unmapped__ = True

    # Per-request cache of live time-bound grants (issue #65), populated by
    # the auth dependency and consulted by
    # ``app.core.permissions.user_has_permission``. The class-level default is
    # the immutable ``None`` sentinel — NEVER a ``[]`` literal, which a mutable
    # class attribute would share across every User instance and leak grants
    # between callers if mutated in place. The dependency assigns a fresh list
    # per request; the read site treats ``None`` as "no grants"
    # (``getattr(user, "_active_time_bound_grants", None) or []``), so a User
    # built outside the auth path (tests, internal construction) reads as empty
    # and is never polluted by another instance.
    _active_time_bound_grants: "list[TimeBoundGrant] | None" = None

    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Auth source: local | ldap | oidc | saml | radius | tacacs
    auth_source: Mapped[str] = mapped_column(String(20), nullable=False, default="local")
    external_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # LDAP DN, OIDC sub, SAML NameID; unique only within its provider
    # The provider an external account belongs to (#1235). External
    # identities are keyed on (auth_provider_id, external_id): two providers
    # of the same type are two authorities, and keying on ``auth_source``
    # (the TYPE) let one of them log in as the other's users. NULL for a
    # local account, for an external account that predates this column and
    # could not be attributed, and for one whose provider was deleted. Such
    # an account is refused at sign-in (``account_link_required`` or
    # ``username_collision``) and is attributed only by an administrator's
    # link (``POST /users/{id}/link-provider``), never by a sign-in: another
    # provider's identical ``sub`` / DN is not the same person. A deleted
    # provider's accounts also lose their ``external_id`` (see the provider
    # delete handler). See ``app.core.auth.user_sync``.
    auth_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth_provider.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    force_password_change: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    @property
    def password_change_required(self) -> bool:
        """``force_password_change`` as enforced: only for a LOCAL account.

        An external account (LDAP / OIDC / SAML / RADIUS / TACACS+) has no
        password here to change — ``/auth/change-password`` requires a local
        one — so honouring the flag on it locks the user out until an admin
        clears it (#1242). Admins can no longer set it on one, and this keeps
        any row that already carries it from staying stuck.
        """
        return self.force_password_change and self.auth_source == "local"

    # MFA — TOTP via pyotp + recovery codes (issue #69). The secret
    # is stored Fernet-encrypted; recovery codes are stored as a
    # Fernet-encrypted JSON list of sha256 hashes (raw codes are
    # only visible to the operator at enrolment, never recoverable
    # from the DB). ``totp_enabled`` flips true only after the
    # operator submits a valid first code via the verify step —
    # before that the secret on disk is a candidate, not active,
    # so a half-finished enrolment doesn't lock anyone out.
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    recovery_codes_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Password-policy bookkeeping (issue #70). ``password_changed_at`` is
    # NULL for external-auth users (no SpatiumDDI-side password) and is
    # backfilled to ``created_at`` for existing local users on migration.
    # ``password_history_encrypted`` is a Fernet blob over a JSON list of
    # prior bcrypt hashes, most-recent-first, capped to the configured
    # ``platform_settings.password_history_count``.
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    password_history_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Account lockout (issue #71). ``failed_login_count`` is reset on
    # any successful login or by an admin via /unlock. While
    # ``failed_login_locked_until`` is set in the future the login
    # handler short-circuits with 403 before checking the password.
    # ``last_failed_login_at`` drives the windowed reset — see
    # ``app.services.account_lockout``.
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    failed_login_locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failed_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # lazy="selectin" so `user.groups` is always populated when the User is
    # fetched via `db.get(User, ...)` in `get_current_user`. The permissions
    # helper walks user.groups → group.roles on every request and cannot do
    # an async lazy-load from the sync code path.
    groups: Mapped[list["Group"]] = relationship(
        "Group", secondary=user_group, back_populates="users", lazy="selectin"
    )
    sessions: Mapped[list["UserSession"]] = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )
    api_tokens: Mapped[list["APIToken"]] = relationship(
        "APIToken",
        foreign_keys="[APIToken.user_id]",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class Group(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "group"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    auth_source: Mapped[str] = mapped_column(String(20), nullable=False, default="local")
    external_dn: Mapped[str | None] = mapped_column(String(1000), nullable=True)  # LDAP DN

    users: Mapped[list[User]] = relationship("User", secondary=user_group, back_populates="groups")
    # lazy="selectin" so `group.roles` loads alongside the Group — see comment on User.groups.
    roles: Mapped[list["Role"]] = relationship(
        "Role", secondary=group_role, back_populates="groups", lazy="selectin"
    )


class Role(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Named permission set. Roles are assigned to groups; permissions within a role
    may be scoped to specific resource IDs (e.g., a particular IPSpace or Subnet).
    """

    __tablename__ = "role"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Permissions stored as JSONB: list of {action, resource_type, resource_id?}.
    # Full grammar is documented in docs/PERMISSIONS.md — keep the two in sync
    # when extending. Examples:
    #   {"action": "*",      "resource_type": "*"}            # superadmin-style
    #   {"action": "read",   "resource_type": "*"}            # viewer
    #   {"action": "admin",  "resource_type": "subnet"}       # CRUD on all subnets
    #   {"action": "write",  "resource_type": "subnet",
    #    "resource_id": "c3f1e7b9-2a5d-…"}                    # scoped to one subnet
    permissions: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)

    groups: Mapped[list[Group]] = relationship(
        "Group", secondary=group_role, back_populates="roles"
    )


class UserSession(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "user_session"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True
    )
    refresh_token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Issue #72 — admin session viewer. ``auth_source`` mirrors the
    # provider this session was minted against ("local" / provider
    # name) so the viewer can show "Logged in via Okta" without a
    # join. ``last_seen_at`` is bumped on each authenticated request
    # (throttled to ~60 s in the auth dep) so the viewer can render
    # a relative-age hint. As wide as ``auth_provider.name`` (#1337).
    auth_source: Mapped[str] = mapped_column(
        String(255), nullable=False, default="local", server_default=sa_text("'local'")
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship("User", back_populates="sessions")


class APIToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "api_token"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    prefix: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # First 8 chars for identification

    # scope: global | user
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default="user")

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="CASCADE"), nullable=True, index=True
    )
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )

    # Optional restriction: list of allowed API path prefixes
    allowed_paths: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    permissions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Coarse-grained scope vocabulary — see issue #74 +
    # ``app.services.api_token_scopes``. Empty list = no scope
    # restriction (token still inherits the owner's RBAC). Non-empty
    # = enforced at the auth layer BEFORE RBAC, so a "read-only"
    # token can never hit a write handler even if its owner's RBAC
    # would otherwise allow it. Closed vocabulary checked at create
    # time; storing free-form strings would let an operator scope a
    # token to a non-existent surface and silently lock themselves
    # out.
    scopes: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    # Per-token resource-instance binding (issue #74 follow-up #374). A list of
    # ``{action, resource_type, resource_id}`` grants in the same grammar as
    # Role.permissions. Empty/None = no resource restriction (current
    # behaviour). Non-empty = the token can only ever NARROW its owner: the
    # effective permission for a request is the INTERSECTION of the owner's
    # RBAC and these grants. Validated at create time to be a subset of what
    # the issuing user holds (you can't mint a token more powerful than
    # yourself). Enforced in app.core.permissions.user_has_permission +
    # token_scope_allows.
    resource_grants: Mapped[list[dict] | None] = mapped_column(JSONB, nullable=True)

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    user: Mapped[User | None] = relationship(
        "User", foreign_keys=[user_id], back_populates="api_tokens"
    )
