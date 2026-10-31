"""Embedded ACME *client* models (issue #438 Phase 1).

Distinct from ``app.models.acme`` — that module is the ACME *provider*
side (an acme-dns-compatible HTTP surface external clients use to prove
control of a SpatiumDDI-hosted FQDN). The two models here are the
*client* side: SpatiumDDI itself acting as an ACME client against a
public CA (Let's Encrypt), driving the RFC 8555 DNS-01 flow to issue a
CA-trusted TLS cert for the appliance Web UI.

Two persistence surfaces:

* ``ACMEClientAccount`` — the operator's ACME account at the CA. One
  account key (Fernet-encrypted) + the CA-assigned account URL. At
  most one account is expected per install in Phase 1, but the table
  doesn't enforce that — the orchestrator picks the most-recent row.
  External Account Binding (EAB) fields are present for CAs that
  require it (ZeroSSL, some private CAs); Let's Encrypt does not.
* ``ACMEOrder`` — one row per issuance attempt. Carries the requested
  domains + challenge type + the CA's order/finalize URLs + a status
  the orchestrator walks (pending → processing → valid|invalid). On
  success ``certificate_id`` points at the ``ApplianceCertificate`` row
  the issued chain landed in.

The issued cert flows into the EXISTING ``ApplianceCertificate``
storage + deploy path with ``source="letsencrypt"`` — there is no
separate cert table here.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, LargeBinary, String, Text
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

# ── Order status values ─────────────────────────────────────────────
# Mirrors the RFC 8555 order/authorization state vocabulary loosely —
# we collapse the CA's per-authorization states into a single
# order-level status the orchestrator + UI care about.
ACME_ORDER_PENDING = "pending"  # created, task enqueued, not yet started
ACME_ORDER_PROCESSING = "processing"  # orchestrator is driving the flow
ACME_ORDER_VALID = "valid"  # cert issued + deployed
ACME_ORDER_INVALID = "invalid"  # failed (see last_error)
ACME_ORDER_STATES = (
    ACME_ORDER_PENDING,
    ACME_ORDER_PROCESSING,
    ACME_ORDER_VALID,
    ACME_ORDER_INVALID,
)

# Challenge type. Phase 1 implements DNS-01 only; the column exists so
# HTTP-01 / TLS-ALPN-01 can land later without a migration.
ACME_CHALLENGE_DNS01 = "dns-01"
ACME_CHALLENGE_HTTP01 = "http-01"
ACME_CHALLENGE_TLSALPN01 = "tls-alpn-01"


class ACMEClientAccount(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """SpatiumDDI's ACME account at a public CA (Let's Encrypt).

    The account key is an RSA/EC private key generated locally and
    used to sign every JWS request to the CA (it is NOT the cert key —
    each order gets its own fresh cert key). The CA returns an
    ``account_url`` (the ``kid`` used in the ``protected`` header of
    every post-newAccount request); we cache it so we don't have to
    re-create the account on every order.

    EAB fields (``eab_kid`` / ``eab_hmac_encrypted``) are only needed
    for CAs that require External Account Binding; Let's Encrypt does
    not, so both are NULL for the common case.
    """

    __tablename__ = "acme_client_account"

    # ACME directory URL the account lives at. One of the LE staging /
    # prod constants in ``app.services.acme_client.engine``, or an
    # operator-supplied private-CA directory. Validated https:// at the
    # API layer.
    directory_url: Mapped[str] = mapped_column(Text, nullable=False)

    # The CA-assigned account URL — the ``kid`` for every JWS request
    # after newAccount. NULL until ``ensure_account`` runs the first
    # newAccount round-trip and caches it here.
    account_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Contact email registered with the CA (expiry notices land here).
    # Optional — LE accepts an account with no contact.
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # PEM-encoded account private key, Fernet-encrypted at rest. NEVER
    # returned in any API response. Signs every JWS to the CA.
    account_key_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # External Account Binding (RFC 8555 §7.3.4) — only for CAs that
    # require it. ``eab_kid`` is the CA-issued key identifier; the HMAC
    # key is Fernet-encrypted at rest. Both NULL for Let's Encrypt.
    eab_kid: Mapped[str | None] = mapped_column(String(255), nullable=True)
    eab_hmac_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)


class ACMEOrder(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One ACME issuance attempt.

    Created by ``POST /api/v1/appliance/acme/issue`` in ``pending``
    state with the requested ``domains``; a Celery task
    (``app.tasks.acme.run_acme_order``) then drives the full DNS-01
    flow via ``app.services.acme_client.orchestrator.run_order``.

    The order is fully re-runnable: the orchestrator flips
    ``processing`` → ``valid`` / ``invalid`` and is idempotent so a
    retry from any state converges. On success ``certificate_id``
    points at the ``ApplianceCertificate`` row carrying the issued
    chain (``source="letsencrypt"``).
    """

    __tablename__ = "acme_order"

    account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("acme_client_account.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Requested SAN domains — the leaf cert covers all of them. First
    # entry is treated as the subject CN by the finalize CSR builder.
    domains: Mapped[list[str]] = mapped_column(JSONB, nullable=False)

    # Challenge type. Phase 1 only solves ``dns-01``; the column gives
    # HTTP-01 / TLS-ALPN-01 a seam without a migration.
    challenge_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ACME_CHALLENGE_DNS01,
        server_default=sa_text("'dns-01'"),
    )

    # Which DNS provider solves the DNS-01 challenge. NULL = the default
    # path (SpatiumDDI's own managed zones via record_ops). A cloud-DNS
    # driver name here is the seam for the deferred cloud-DNS DNS-01
    # path; Phase 1 only honours the default.
    dns_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Order lifecycle — see ACME_ORDER_* constants.
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ACME_ORDER_PENDING,
        server_default=sa_text("'pending'"),
    )

    # CA-assigned URLs, cached from the newOrder response so the
    # orchestrator can re-poll / re-finalize without re-creating the
    # order. Both NULL until the order is created at the CA.
    order_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    finalize_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # On success, the ApplianceCertificate row the issued chain landed
    # in. ON DELETE SET NULL — operator deleting the cert row shouldn't
    # take down the order history.
    certificate_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("appliance_certificate.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Human-readable failure reason on ``invalid`` orders (surfaced in
    # the UI status block). NULL on pending / valid orders.
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Phase 3 manual DNS-01 fallback. ``allow_manual`` is the operator's
    # per-order opt-in to solve DNS-01 for domains whose zone SpatiumDDI
    # does NOT manage. ``manual_challenges`` is the list of
    # ``{fqdn, record_name, txt_value}`` the orchestrator publishes (while
    # the order is ``processing``) for the UI to show the operator which
    # TXT records to add at their own DNS provider; cleared once they
    # validate.
    allow_manual: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    manual_challenges: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )

    # #3067 — whether a successful fresh issue makes the cert the sole
    # active (Web UI) certificate, deploying it to nginx. True is what
    # issuance always did; a certificate-store-only caller (no ``admin`` on
    # ``appliance``) issuing a DoT / DoH / DoQ cert sets it false. A renewal
    # never changes ``is_active`` either way.
    activate_on_issue: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )


class ACMEHTTPChallenge(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A pending http-01 challenge token → key-authorization mapping (#438
    Phase 4).

    The CA fetches ``http://<domain>/.well-known/acme-challenge/<token>``
    and expects the key-authorization back verbatim. The unauthenticated
    well-known endpoint looks the token up here, so the mapping must be
    cluster-global (DB-backed, not per-pod memory) to work behind the
    MetalLB VIP fronting N frontend replicas. Rows are written before the
    client tells the CA "ready" and deleted after validation.
    """

    __tablename__ = "acme_http_challenge"

    # The challenge token — the last path segment the CA fetches. Indexed
    # unique so the well-known endpoint is a single point-lookup.
    token: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    # The exact body to serve: ``<token>.<base64url(jwk_thumbprint)>``.
    key_authorization: Mapped[str] = mapped_column(Text, nullable=False)
    order_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("acme_order.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


__all__ = [
    "ACMEClientAccount",
    "ACMEHTTPChallenge",
    "ACMEOrder",
    "ACME_ORDER_PENDING",
    "ACME_ORDER_PROCESSING",
    "ACME_ORDER_VALID",
    "ACME_ORDER_INVALID",
    "ACME_ORDER_STATES",
    "ACME_CHALLENGE_DNS01",
    "ACME_CHALLENGE_HTTP01",
    "ACME_CHALLENGE_TLSALPN01",
]
