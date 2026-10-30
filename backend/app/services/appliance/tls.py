"""Certificate parsing + validation for the appliance Web UI cert
management surface (Phase 4b.1).

All operations are pure Python (cryptography lib) — no system calls,
no filesystem writes, no nginx interaction. The router calls into
``parse_pem_certificate`` + ``validate_key_matches_cert`` on upload to
populate the model row's identity columns + reject mismatched pairs
before persisting anything.

Phase 4b.2 will add a ``write_active_cert_to_filesystem`` helper that
materializes the active row into ``/etc/nginx/certs/active.{pem,key}``
and reloads nginx. Phase 4b.3 + 4b.4 will add CSR + ACME issuance
helpers. Keeping those out of this file so the import surface stays
small for the basic upload flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

# #3045 — where an operator manages ``ApplianceCertificate`` rows, for the
# texts that send them there (the DoT / DoH refusal, the expiry alert). Since
# #404 the Web UI Certificate page is an entry in the Appliance page's Fleet
# side list, and Fleet shows it only on an appliance-hosted control plane; a
# Docker or Kubernetes control plane reaches the same store through the API.
WEB_UI_CERTIFICATE_PAGE = "Appliance → Fleet → Web UI Certificate"
CERTIFICATE_API = "POST /api/v1/appliance/tls/upload"
ACME_ISSUE_API = "POST /api/v1/appliance/acme/issue"


def certificate_store_location(appliance_mode: bool) -> str:
    """Name the place a certificate is uploaded or issued, as a noun phrase."""
    if appliance_mode:
        return WEB_UI_CERTIFICATE_PAGE
    return (
        f"the API ({CERTIFICATE_API}, or {ACME_ISSUE_API} for Let's Encrypt; "
        "a Docker or Kubernetes control plane has no certificate page)"
    )


class TLSValidationError(ValueError):
    """Raised when uploaded PEMs fail parsing or key/cert mismatch.

    The router translates these into a 422 with the message string
    visible to the operator.
    """


# Supported key types for CSR generation. RSA-2048 stays the default
# because it's universally accepted by public CAs and private intermediates;
# EC-P256 is the modern alternative (smaller key, faster handshakes); EC-P384
# for compliance regimes that mandate stronger curves; RSA-3072/4096 for
# the rare CA that won't sign anything below 3072.
KEY_TYPES = ("rsa-2048", "rsa-3072", "rsa-4096", "ec-p256", "ec-p384")


@dataclass(frozen=True)
class CSRSubject:
    """Operator-supplied subject fields for a CSR.

    All optional except common_name. The router accepts an open-ended
    dict and constructs this dataclass so future fields don't need
    a service-layer signature change.
    """

    common_name: str
    organization: str | None = None
    organizational_unit: str | None = None
    country: str | None = None  # 2-letter ISO code
    state: str | None = None
    locality: str | None = None
    email: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "common_name": self.common_name,
            "organization": self.organization,
            "organizational_unit": self.organizational_unit,
            "country": self.country,
            "state": self.state,
            "locality": self.locality,
            "email": self.email,
        }


@dataclass(frozen=True)
class CertificateInfo:
    """Identity extracted from a parsed PEM certificate.

    Populates the ApplianceCertificate model's display columns so the
    UI never has to re-parse the PEM on every list call.
    """

    subject_cn: str
    issuer_cn: str
    sans: list[str]
    fingerprint_sha256: str
    valid_from: datetime
    valid_to: datetime


def parse_pem_certificate(cert_pem: str) -> CertificateInfo:
    """Parse a PEM-encoded x509 certificate (leaf, or leaf+chain).

    Multi-cert PEMs (the usual "leaf + intermediates" file operators
    paste) are handled by ``x509.load_pem_x509_certificates``; we use
    the first cert in the bundle as the leaf — that's the one nginx
    will serve, and the one whose fingerprint + validity matter for
    the UI's "expires in N days" display.

    Raises:
        TLSValidationError: parse failed, empty bundle, or no Common
            Name on the subject.
    """
    cert_bytes = cert_pem.encode("utf-8")
    try:
        certs = x509.load_pem_x509_certificates(cert_bytes)
    except ValueError as exc:
        raise TLSValidationError(f"not a valid PEM certificate: {exc}") from exc

    if not certs:
        raise TLSValidationError("no certificates found in PEM bundle")

    leaf = certs[0]

    subject_cn = _common_name(leaf.subject) or _first_san(leaf) or "<no CN>"
    issuer_cn = _common_name(leaf.issuer) or "<unknown issuer>"
    sans = _extract_sans(leaf)
    fingerprint = _format_fingerprint(leaf.fingerprint(hashes.SHA256()))

    # cryptography 42+ exposes timezone-aware UTC accessors; the older
    # naïve accessors are deprecated. Use the new ones so we don't get
    # a DeprecationWarning + naïve datetimes mixing with our timezone-
    # aware DateTime columns.
    valid_from = leaf.not_valid_before_utc
    valid_to = leaf.not_valid_after_utc

    return CertificateInfo(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        sans=sans,
        fingerprint_sha256=fingerprint,
        valid_from=valid_from,
        valid_to=valid_to,
    )


def validate_key_matches_cert(cert_pem: str, key_pem: str) -> None:
    """Confirm the supplied private key signs what the cert says it does.

    Compares the cert's SubjectPublicKeyInfo to the key's derived public
    key — every supported algorithm (RSA, ECDSA, Ed25519, Ed448, DSA)
    is handled by the same equality check on the serialized public-key
    bytes, so we don't need per-algorithm branches.

    Raises:
        TLSValidationError: parse failed on either input, or the
            public keys don't match.
    """
    try:
        certs = x509.load_pem_x509_certificates(cert_pem.encode("utf-8"))
    except ValueError as exc:
        raise TLSValidationError(f"cert parse failed: {exc}") from exc
    if not certs:
        raise TLSValidationError("empty cert PEM")
    leaf = certs[0]

    try:
        # password=None — encrypted keys aren't supported here; operators
        # can decrypt before uploading. We could add a passphrase field
        # later but the value is marginal vs. the UX cost.
        private_key = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise TLSValidationError(
            f"key parse failed (encrypted keys not supported — decrypt first): {exc}"
        ) from exc

    if not isinstance(
        private_key,
        (
            rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
            dsa.DSAPrivateKey,
        ),
    ):
        raise TLSValidationError(f"unsupported key algorithm: {type(private_key).__name__}")

    cert_pub_bytes = leaf.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if cert_pub_bytes != key_pub_bytes:
        raise TLSValidationError("private key does not match the certificate's public key")


# ── Helpers (private) ───────────────────────────────────────────────


def _common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")


def _first_san(cert: x509.Certificate) -> str | None:
    """Fall back to the first DNS SAN when there's no CN on the subject.

    Modern certs (Let's Encrypt, most public CAs) often omit the CN
    entirely and put every name in the SAN extension instead.
    """
    sans = _extract_sans(cert)
    return sans[0] if sans else None


def _extract_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    sans: list[str] = []
    for entry in ext.value:
        if isinstance(entry, x509.DNSName):
            sans.append(entry.value)
        elif isinstance(entry, x509.IPAddress):
            sans.append(str(entry.value))
    return sans


def _format_fingerprint(raw: bytes) -> str:
    """Render as ``AB:CD:EF:…`` (matches OpenSSL output, easy to compare)."""
    return ":".join(f"{b:02X}" for b in raw)


# ── CSR generation (Phase 4b.3) ─────────────────────────────────────


def generate_csr_and_key(
    subject: CSRSubject,
    sans: list[str],
    key_type: str = "rsa-2048",
) -> tuple[str, str]:
    """Generate a fresh private key + signed CSR for the given subject.

    Returns ``(csr_pem, key_pem)`` — both PKCS-standard PEM strings.
    The router caller is responsible for Fernet-encrypting the key
    before persisting; this helper deals only in unwrapped PEM so it
    stays testable without app config.

    SANs go into a SubjectAlternativeName extension. Mostly-DNS list
    is the common case; bare IPs (``192.168.1.10``) are auto-detected
    and routed into IPAddress entries so private-CA workflows that
    want IP SANs Just Work.

    Raises:
        TLSValidationError: invalid key_type, no common_name, or a
            subject/SAN that X.509 itself refuses — a CommonName over
            64 BYTES (the request schema bounds characters, so a long
            or multibyte CN passes validation and fails here) or a SAN
            that is not an IDNA A-label. Not theoretical: both are
            reachable from the request body, and both were 500s until
            they were translated into this error.
    """
    if key_type not in KEY_TYPES:
        raise TLSValidationError(
            f"unsupported key_type {key_type!r} — pick one of {', '.join(KEY_TYPES)}"
        )
    cn = subject.common_name.strip()
    if not cn:
        raise TLSValidationError("common_name is required")

    # ``x509.NameAttribute``/``x509.DNSName`` enforce X.509's own limits that
    # the request schema cannot fully express — a CommonName is capped at 64
    # BYTES (the schema bounds characters, so a 65-255-char or multibyte CN
    # passes validation then raises here), and a SAN must be an IDNA A-label
    # (a non-ASCII hostname like "你好.test" raises). Both surfaced as
    # a 500; the endpoint declares 422 for bad subject input, so translate any
    # cryptography ValueError into the validation error the contract promises.
    try:
        name_attrs: list[x509.NameAttribute] = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
        if subject.country:
            name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject.country))
        if subject.state:
            name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject.state))
        if subject.locality:
            name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject.locality))
        if subject.organization:
            name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organization))
        if subject.organizational_unit:
            name_attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organizational_unit)
            )
        if subject.email:
            name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject.email))

        builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(name_attrs))

        san_entries = _build_san_entries(sans)
        if san_entries:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_entries), critical=False
            )
    except ValueError as exc:
        raise TLSValidationError(f"invalid subject or SAN: {exc}") from exc

    # After the subject/SAN gate, not before: an RSA-4096 keygen is the most
    # expensive thing this function does, and a request destined for a 422
    # should not pay for one.
    private_key = _generate_private_key(key_type)

    # RSA + ECDSA use SHA-256; Ed25519/Ed448 don't take a hash arg, but
    # we don't generate those here (no public CA supports them yet so
    # they'd be a dead-end CSR).
    try:
        csr = builder.sign(private_key, hashes.SHA256())
    except Exception as exc:  # pragma: no cover — cryptography is well-tested
        raise TLSValidationError(f"CSR signing failed: {exc}") from exc

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return csr_pem, key_pem


def _generate_private_key(key_type: str):
    if key_type == "rsa-2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type == "rsa-3072":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if key_type == "rsa-4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if key_type == "ec-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "ec-p384":
        return ec.generate_private_key(ec.SECP384R1())
    # Should never reach — KEY_TYPES check in caller. Defensive.
    raise TLSValidationError(f"unsupported key_type {key_type}")


def _build_san_entries(sans: list[str]) -> list[x509.GeneralName]:
    """Translate a flat string list into typed SAN entries.

    Detect IPs (v4 + v6) so a SAN like ``"192.168.1.10"`` becomes an
    IPAddress entry, not a DNSName the cert verifier will refuse.
    DNS hostnames (`*.example.com` / `example.com`) become DNSName.
    Empty / whitespace-only entries dropped.
    """
    import ipaddress

    entries: list[x509.GeneralName] = []
    for raw in sans:
        s = raw.strip()
        if not s:
            continue
        try:
            ip = ipaddress.ip_address(s)
            entries.append(x509.IPAddress(ip))
        except ValueError:
            entries.append(x509.DNSName(s))
    return entries
