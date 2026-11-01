"""TLS certificate probe (issue #118).

Connect to a target endpoint over TLS, capture the served certificate +
chain, validate the chain against the system trust store, and write the
observation to a ``tls_cert_probe`` row while denormalising the latest
identity onto the ``tls_cert_target``.

Two-pass design:

1. **Capture pass** (pyOpenSSL ``get_peer_cert_chain()`` with verification
   OFF) — grabs the chain the server PRESENTS (leaf + intermediates) even
   when it's broken/untrusted, so the detail view can show every cert.
   stdlib ssl on Python 3.12 only exposes the leaf, hence pyOpenSSL. The
   trust-anchor root (which servers normally omit) is then resolved from
   the system CA store and appended.
2. **Verify pass** (``ssl.create_default_context()`` with
   ``check_hostname=False`` + ``CERT_REQUIRED``) — judges chain TRUST only
   (``chain_valid``); the hostname match is computed separately from the
   leaf so a pure name mismatch isn't mislabelled chain-invalid. Transport
   failures (refused / timeout / DNS) → ``unreachable``.

Reuses the cert-parse helpers from ``app.services.nettools.socket_tools``
so we don't re-implement x509 extraction. SSRF: the host is re-resolved
at probe time and every resolved IP re-checked against the blocked-range
list (closing the documented hostname-into-blocked-range hole that the
shape-only ``assert_target_allowed`` validator leaves open).

``probe_one`` mirrors ``app.services.domain_refresh.refresh_one_domain``:
it writes the result back and stamps ``next_check_at`` but does NOT commit
— the caller owns the session.
"""

from __future__ import annotations

import select
import socket
import ssl
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from OpenSSL import SSL, crypto
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exc_text import describe_exc
from app.models.tls_cert import (
    IDENTITY_FIELDS,
    STATE_EXPIRED,
    STATE_EXPIRING,
    STATE_MISMATCH,
    STATE_OK,
    STATE_UNKNOWN,
    STATE_UNREACHABLE,
    TLSCertProbe,
    TLSCertTarget,
)
from app.services.nettools.schemas import is_blocked_target
from app.services.nettools.socket_tools import (
    _common_names,
    _hostname_matches,
    _rfc4514,
    _san_dns_names,
)

logger = structlog.get_logger(__name__)

# Default connect timeout per pass (seconds). The synchronous probe runs
# in a worker thread / under the scheduled task; keep it tight so a dead
# host doesn't stall the dispatcher.
PROBE_TIMEOUT = 8.0

# The "expiring soon" window used for the derived state bucket (the UI
# pill + count_tls_targets_by_state). Distinct from any alert rule's own
# threshold_days — this is just the cosmetic bucket boundary.
STATE_EXPIRING_WARN_DAYS = 30


def derive_tls_state(
    *,
    ok: bool,
    not_after: datetime | None,
    chain_valid: bool | None,
    hostname_matches: bool | None,
    now: datetime,
    warn_days: int = STATE_EXPIRING_WARN_DAYS,
) -> str:
    """Single source of truth for the target's derived health bucket.

    Order (most-urgent wins): unreachable > expired > expiring > mismatch > ok.
    """
    if not ok:
        return STATE_UNREACHABLE
    if not_after is None:
        return STATE_UNKNOWN
    na = not_after if not_after.tzinfo else not_after.replace(tzinfo=UTC)
    if now >= na:
        return STATE_EXPIRED
    if (na - now).days <= warn_days:
        return STATE_EXPIRING
    if chain_valid is False or hostname_matches is False:
        return STATE_MISMATCH
    return STATE_OK


@dataclass(frozen=True)
class ProbeOutcome:
    """Raw result of reaching the endpoint (no DB)."""

    ok: bool
    error: str | None
    identity: dict[str, Any] | None  # IDENTITY_FIELDS values
    hostname_matches: bool | None
    leaf_pem: str | None
    chain_pem: str | None


@dataclass(frozen=True)
class ProbeResult:
    """What probe_one observed + what changed (for audit gating)."""

    target_id: uuid.UUID
    ok: bool
    state: str
    error: str | None
    fingerprint_changed: bool
    state_changed: bool
    chain_valid_changed: bool

    @property
    def any_meaningful_change(self) -> bool:
        return self.fingerprint_changed or self.state_changed or self.chain_valid_changed


# ── resolution / SSRF ────────────────────────────────────────────────


def _resolve_safe_ip(host: str) -> tuple[str | None, str | None]:
    """Resolve ``host`` ONCE and return ``(connect_ip, None)`` for the first
    usable answer, or ``(None, error)`` if it can't resolve or ANY answer is
    in a blocked range.

    Closing the SSRF hole properly requires connecting to *this* IP literal
    (not re-resolving the hostname at connect time) — otherwise a DNS-
    rebinding attacker returns a public IP for the check and 169.254.169.254
    / 127.0.0.1 for the connect (the IP that passed the check is never the
    IP we'd connect to). We reject if any answer is blocked (an attacker can
    return ``[public, metadata]``) and connect to the chosen literal. An IP
    literal host is covered too — getaddrinfo echoes it and is_blocked_target
    classifies it.
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return None, f"DNS resolution failed: {exc}"
    chosen: str | None = None
    for info in infos:
        ip = info[4][0]  # sockaddr address element (str for AF_INET/INET6)
        if not isinstance(ip, str):
            continue
        if is_blocked_target(ip):
            return None, (
                f"{host!r} resolves to {ip} which is in a blocked range "
                "(loopback / link-local / cloud-metadata) and will not be probed"
            )
        if chosen is None:
            chosen = ip
    if chosen is None:
        return None, f"{host!r} did not resolve to a usable address"
    return chosen, None


# ── cert parsing ─────────────────────────────────────────────────────


def _key_params(cert: x509.Certificate) -> tuple[str | None, int | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return type(pub).__name__, None


def _fingerprint(cert: x509.Certificate) -> str:
    # Colon-hex uppercase — matches `openssl x509 -fingerprint -sha256`.
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def _sig_algo(cert: x509.Certificate) -> str | None:
    try:
        name = cert.signature_algorithm_oid._name  # e.g. sha256WithRSAEncryption
        if name and name != "Unknown OID":
            return name
    except Exception:  # noqa: BLE001
        pass
    try:
        return cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001
        return None


def _parse_identity(
    leaf_der: bytes, chain_ders: list[bytes], server_name: str
) -> tuple[dict[str, Any], bool]:
    cert = x509.load_der_x509_certificate(leaf_der)
    san = _san_dns_names(cert)
    cn = _common_names(cert.subject)
    issuer_cn = _common_names(cert.issuer)
    key_algo, key_size = _key_params(cert)
    return {
        "serial": format(cert.serial_number, "x"),
        "subject_cn": (cn[0] if cn else None),
        "issuer_cn": (issuer_cn[0] if issuer_cn else None),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "sans_json": san,
        "key_algo": key_algo,
        "key_size": key_size,
        "sig_algo": _sig_algo(cert),
        "chain_depth": len(chain_ders) or 1,
        "self_signed": _rfc4514(cert.subject) == _rfc4514(cert.issuer),
        "fingerprint_sha256": _fingerprint(cert),
        # chain_valid / chain_error filled by the caller (validation pass).
        "chain_valid": None,
        "chain_error": None,
    }, _hostname_matches(server_name, san, cn)


def _pem(der: bytes) -> str:
    return (
        x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode("ascii")
    )


def parse_chain_pem(pem: str | None) -> list[dict[str, Any]]:
    """Parse a concatenated PEM bundle into per-cert summaries, leaf →
    intermediate(s) → root, for the cert detail view."""
    if not pem:
        return []
    try:
        certs = x509.load_pem_x509_certificates(pem.encode())
    except Exception:  # noqa: BLE001 — best-effort parse
        return []
    out: list[dict[str, Any]] = []
    for i, c in enumerate(certs):
        cn = _common_names(c.subject)
        icn = _common_names(c.issuer)
        self_signed = _rfc4514(c.subject) == _rfc4514(c.issuer)
        role = "leaf" if i == 0 else ("root" if self_signed else "intermediate")
        key_algo, key_size = _key_params(c)
        try:
            bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca: bool | None = bool(bc.ca)
        except Exception:  # noqa: BLE001
            is_ca = None
        out.append(
            {
                "position": i,
                "role": role,
                "subject_cn": (cn[0] if cn else _rfc4514(c.subject)),
                "issuer_cn": (icn[0] if icn else _rfc4514(c.issuer)),
                "serial": format(c.serial_number, "x"),
                "not_before": c.not_valid_before_utc.isoformat(),
                "not_after": c.not_valid_after_utc.isoformat(),
                "key_algo": key_algo,
                "key_size": key_size,
                "sig_algo": _sig_algo(c),
                "is_ca": is_ca,
                "self_signed": self_signed,
                "fingerprint_sha256": _fingerprint(c),
            }
        )
    return out


# ── the probe ────────────────────────────────────────────────────────


def _served_chain_ders(connect_ip: str, port: int, sni: str, timeout: float) -> list[bytes]:
    """Capture the chain the server PRESENTS (leaf + intermediates) via
    pyOpenSSL — stdlib ssl on Python 3.12 only exposes the leaf. Verification
    is disabled so a broken / untrusted chain is still captured for display;
    trust is judged separately by :func:`_verify_trust`. Leaf-first DERs.
    Raises on transport / handshake failure (the caller classifies)."""
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    # Floor at TLS 1.2 — TLS 1.0/1.1 are deprecated, and a monitor probing
    # 2026-era endpoints shouldn't negotiate them. set_options(OP_NO_*) is
    # the explicit, statically-recognised form (set_min_proto_version alone
    # isn't seen as remediation by static analysis). Verification stays off
    # (we capture untrusted chains); trust is judged by _verify_trust.
    ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
    ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *_a: True)
    sock = socket.create_connection((connect_ip, port), timeout=timeout)
    # Non-blocking + a select() deadline: a timeout-mode socket makes
    # pyOpenSSL's do_handshake raise WantReadError, so drive it explicitly.
    sock.setblocking(False)
    deadline = time.monotonic() + timeout
    try:
        conn = SSL.Connection(ctx, sock)
        conn.set_connect_state()
        try:
            conn.set_tlsext_host_name(sni.encode("idna"))
        except Exception:  # noqa: BLE001 — non-IDNA SNI
            conn.set_tlsext_host_name(sni.encode("ascii", "ignore"))
        while True:
            try:
                conn.do_handshake()
                break
            except (SSL.WantReadError, SSL.WantWriteError) as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("TLS handshake timed out") from exc
                want_read = isinstance(exc, SSL.WantReadError)
                rlist = [sock] if want_read else []
                wlist = [] if want_read else [sock]
                if not select.select(rlist, wlist, [], remaining)[0 if want_read else 1]:
                    raise TimeoutError("TLS handshake timed out") from exc
        chain = conn.get_peer_cert_chain() or []
        ders = [crypto.dump_certificate(crypto.FILETYPE_ASN1, c) for c in chain]
        try:
            conn.shutdown()
        except Exception:  # noqa: BLE001
            pass
        return ders
    finally:
        sock.close()


def _verify_trust(
    connect_ip: str, port: int, sni: str, timeout: float
) -> tuple[bool | None, str | None]:
    """Judge chain TRUST against the system store (hostname NOT checked — the
    name match is computed separately, so a pure name mismatch isn't reported
    as chain-invalid). (True, None) trusted; (False, error) verification
    failure; (None, None) when a transport hiccup leaves it undetermined."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # explicit (default, but pinned)
    ctx.check_hostname = False
    try:
        with socket.create_connection((connect_ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, str(exc)
    except (ssl.SSLError, OSError):
        return None, None


_TRUST_STORE: dict[str, x509.Certificate] | None = None


def _trust_store() -> dict[str, x509.Certificate]:
    """Lazy {subject_rfc4514: cert} index of the system CA bundle — used to
    resolve the root (servers normally omit it; it lives in the store)."""
    global _TRUST_STORE
    if _TRUST_STORE is None:
        idx: dict[str, x509.Certificate] = {}
        for path in (
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ):
            try:
                data = Path(path).read_bytes()
            except OSError:
                continue
            try:
                for cert in x509.load_pem_x509_certificates(data):
                    idx[_rfc4514(cert.subject)] = cert
            except Exception:  # noqa: BLE001
                pass
            break
        _TRUST_STORE = idx
    return _TRUST_STORE


def _append_root(chain_ders: list[bytes]) -> list[bytes]:
    """Append the trust-anchor root when the server-sent chain's topmost cert
    isn't already self-signed (servers normally don't send the root)."""
    if not chain_ders:
        return chain_ders
    try:
        top = x509.load_der_x509_certificate(chain_ders[-1])
    except Exception:  # noqa: BLE001
        return chain_ders
    if _rfc4514(top.subject) == _rfc4514(top.issuer):
        return chain_ders  # already a self-signed root
    root = _trust_store().get(_rfc4514(top.issuer))
    if root is not None:
        return chain_ders + [root.public_bytes(serialization.Encoding.DER)]
    return chain_ders


def fetch_endpoint(
    host: str, port: int, server_name: str | None, *, timeout: float = PROBE_TIMEOUT
) -> ProbeOutcome:
    """Synchronous two-pass probe. Run under ``asyncio.to_thread``."""
    sni = server_name or host

    # Resolve ONCE and pin the IP we connect to (DNS-rebinding-safe).
    connect_ip, resolve_err = _resolve_safe_ip(host)
    if connect_ip is None:
        return _failure(resolve_err or f"{host!r} could not be resolved")

    # Capture the served chain (leaf + intermediates); verification off so a
    # broken/untrusted chain is still captured for display.
    try:
        chain_ders = _served_chain_ders(connect_ip, port, sni, timeout)
    except TimeoutError:
        return _failure(f"TLS handshake timed out after {timeout:.1f}s")
    except (SSL.Error, ssl.SSLError, OSError, socket.gaierror) as exc:
        return _failure(f"TLS connection failed: {describe_exc(exc)}")

    if not chain_ders:
        return _failure("server presented no certificate")

    leaf_der = chain_ders[0]
    # Resolve + append the root from the trust store (servers omit it).
    chain_ders = _append_root(chain_ders)
    # Judge trust separately (hostname computed from the leaf below).
    chain_valid, chain_error = _verify_trust(connect_ip, port, sni, timeout)

    try:
        identity, hostname_matches = _parse_identity(leaf_der, chain_ders, sni)
    except Exception as exc:  # noqa: BLE001 — surface parse failures cleanly
        logger.warning("tls_cert_parse_failed", host=host, error=str(exc))
        return _failure(f"failed to parse certificate: {describe_exc(exc)}")

    identity["chain_valid"] = chain_valid
    identity["chain_error"] = chain_error
    leaf_pem = _safe_pem(leaf_der)
    chain_pem = "".join(_safe_pem(d) for d in chain_ders) if chain_ders else None
    return ProbeOutcome(
        ok=True,
        error=None,
        identity=identity,
        hostname_matches=hostname_matches,
        leaf_pem=leaf_pem,
        chain_pem=chain_pem,
    )


def _safe_pem(der: bytes) -> str:
    try:
        return _pem(der)
    except Exception:  # noqa: BLE001
        return ""


def _failure(error: str) -> ProbeOutcome:
    return ProbeOutcome(
        ok=False,
        error=error,
        identity=None,
        hostname_matches=None,
        leaf_pem=None,
        chain_pem=None,
    )


async def probe_one(
    db: AsyncSession,
    target: TLSCertTarget,
    *,
    default_interval_hours: int,
    now: datetime | None = None,
) -> ProbeResult:
    """Probe one target, write a probe row + update the target. No commit."""
    import asyncio  # noqa: PLC0415 — local import keeps module import cheap

    when = now or datetime.now(UTC)
    prev_fp = target.fingerprint_sha256
    prev_state = target.state
    prev_chain_valid = target.chain_valid

    outcome = await asyncio.to_thread(fetch_endpoint, target.host, target.port, target.server_name)

    hours = target.interval_hours or default_interval_hours
    hours = max(1, min(168, hours))
    target.last_checked_at = when
    target.next_check_at = when + timedelta(hours=hours)

    probe = TLSCertProbe(target_id=target.id, probed_at=when, ok=outcome.ok)

    if outcome.ok and outcome.identity is not None:
        ident = outcome.identity
        state = derive_tls_state(
            ok=True,
            not_after=ident.get("not_after"),
            chain_valid=ident.get("chain_valid"),
            hostname_matches=outcome.hostname_matches,
            now=when,
        )
        # Copy identity onto both the probe snapshot and the target's
        # denormalised columns.
        for field in IDENTITY_FIELDS:
            setattr(probe, field, ident.get(field))
            setattr(target, field, ident.get(field))
        probe.leaf_pem = outcome.leaf_pem
        probe.chain_pem = outcome.chain_pem
        probe.error = None
        target.last_error = None
        target.consecutive_failures = 0
    else:
        # Transport / handshake failure — PRESERVE the prior identity so a
        # transient outage doesn't wipe the last-known cert (and doesn't
        # fire a spurious "changed" alert). Only flip state + failure count.
        state = STATE_UNREACHABLE
        probe.error = outcome.error
        target.last_error = outcome.error
        target.consecutive_failures = (target.consecutive_failures or 0) + 1

    probe.state = state
    target.state = state
    db.add(probe)

    new_fp = target.fingerprint_sha256
    fingerprint_changed = bool(outcome.ok and prev_fp and new_fp and prev_fp != new_fp)
    return ProbeResult(
        target_id=target.id,
        ok=outcome.ok,
        state=state,
        error=outcome.error,
        fingerprint_changed=fingerprint_changed,
        state_changed=(prev_state != state),
        # Guard the first probe (prev is None) so a fresh target's first
        # observation isn't logged as a chain-validity "change".
        chain_valid_changed=(
            outcome.ok
            and prev_chain_valid is not None
            and prev_chain_valid is not target.chain_valid
        ),
    )
