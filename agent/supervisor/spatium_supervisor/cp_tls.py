"""Verify the control plane's TLS certificate (#1219).

Before this, every supervisor → control plane request ran with verification
OFF (the appliance chart set ``SPATIUM_INSECURE_SKIP_TLS_VERIFY=1``
unconditionally), and nothing was pinned in its place. The heartbeat
response carries the platform-wide DNS / DHCP agent keys and the slot image
URL plus the sha256 that is the ONLY integrity check on it, so anyone on the
path could read the keys and serve a node a root filesystem of their choice.

The model:

* **Pin on first contact.** The first time the supervisor talks to an
  ``https`` control plane (registration, in practice) it records the leaf
  certificate the server presented, and from then on trusts exactly that
  certificate. Verification happens in the TLS handshake, so no request, and
  no session token, is sent to a server that does not hold the pinned key.
  Pinning the exact certificate makes the hostname irrelevant, which is what
  lets an operator type an IP.
* **Rotate through the appliance CA.** The Web UI certificate changes in
  normal operation (a self-signed one is re-minted when a member joins or
  the VIP changes; an operator uploads one; ACME renews one). When the
  presented certificate is not the pinned one, the supervisor fetches the
  control plane's list of served certificates, signed by the appliance CA
  whose certificate it received at approval, over a connection to the NEW
  certificate, and re-pins only if the CA vouches for it.
* **Check the first-contact pin once approved.** Trust on first use is only
  as good as that first contact. Once the CA arrives, the supervisor checks
  that the certificate it pinned is one the CA vouches for, and says so
  loudly if not.

What this does not cover, stated so nobody reads more into it: an attacker
present at pairing who also substitutes the CA certificate the supervisor
receives at approval. That needs an out-of-band check (the operator comparing
the fingerprint this module logs with the one shown under Appliance -> TLS on
the control plane).

Plain ``http`` control-plane URLs are left alone: the in-cluster
``http://...svc`` URL control-plane members use has no certificate to verify,
and an operator-typed ``http://`` URL is followed to its ``https://``
redirect, whose certificate is then pinned like any other.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import structlog
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

from .cert_auth import CA_CHAIN_FILENAME

log = structlog.get_logger(__name__)

PIN_FILENAME = "control-plane.pem"
PIN_SET_PATH = "/api/v1/appliance/supervisor/tls-pins"
PIN_SET_ALGORITHM = "rsa-pss-sha256"
#: A signed list older than this is refused, so one captured before a
#: rotation cannot be replayed afterwards to vouch for a retired certificate.
PIN_SET_MAX_AGE = timedelta(days=1)
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
_CONNECT_TIMEOUT_S = 10.0

# The pin file is read by every proxy thread and written by the main loop.
_lock = threading.Lock()
# ``http://`` URL -> the ``https://`` it redirects to (or None: it does not).
_redirects: dict[str, str | None] = {}
# Whether the first-contact pin has been checked against the CA this process.
# Per-process flags, in a mutable holder rather than ``global`` rebinding:
# whether the first-contact pin has been checked against the CA, and whether
# the skip-verify warning has been logged.
_state = {"vouch_checked": False, "skip_warned": False}


class PinSetError(Exception):
    """A signed certificate list that cannot be trusted."""


class PinSetUnavailable(PinSetError):
    """The control plane could not produce the list right now (a 5xx, say,
    while the api restarts): worth asking again, unlike a bad signature."""


# ── the pin ──────────────────────────────────────────────────────────────────


def _pin_path(state_dir: Path) -> Path:
    return state_dir / "tls" / PIN_FILENAME


def load_pins(state_dir: Path) -> str | None:
    """The pinned certificate(s) as PEM, or None before first contact."""
    try:
        pem = _pin_path(state_dir).read_text(encoding="ascii")
    except OSError:
        return None
    return pem if "BEGIN CERTIFICATE" in pem else None


def _save_pins(state_dir: Path, pem: str) -> None:
    path = _pin_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(pem, encoding="ascii")
    os.replace(tmp, path)


def _certs(pem: str) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(pem.encode("ascii"))


def cert_sha256(pem: str) -> str:
    """SHA-256 of the first certificate's DER, lowercase hex (the wire form)."""
    return hashlib.sha256(_certs(pem)[0].public_bytes(Encoding.DER)).hexdigest()


def display_fingerprint(sha256_hex: str) -> str:
    """``AB:CD:...``, the form the control plane's TLS page shows."""
    return ":".join(sha256_hex[i : i + 2] for i in range(0, len(sha256_hex), 2)).upper()


def _pinned_fingerprints(pem: str) -> set[str]:
    return {hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest() for c in _certs(pem)}


def pinned_context(pem: str) -> ssl.SSLContext:
    """A TLS context that trusts exactly the certificate(s) in ``pem``.

    ``VERIFY_X509_PARTIAL_CHAIN`` lets a pinned leaf be the trust anchor even
    when it is not self-signed (an uploaded or ACME certificate). The
    hostname is not checked: the pinned certificate IS the identity, and an
    operator may well have typed an IP the certificate does not name.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=pem)
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return ctx


def presented_leaf_pem(url: str, timeout: float = _CONNECT_TIMEOUT_S) -> str:
    """The leaf certificate the server at ``url`` presents, unverified."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or 443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ipaddress.ip_address(host)
        sni: str | None = None  # SNI carries names, never addresses
    except ValueError:
        sni = host
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError(f"{host}:{port} presented no certificate")
    return ssl.DER_cert_to_PEM_cert(der)


# ── which URL carries a certificate ──────────────────────────────────────────


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _in_cluster(host: str) -> bool:
    return host.endswith(".svc") or ".svc." in host or host.endswith(".cluster.local")


def tls_url(url: str) -> str | None:
    """The ``https://`` URL whose certificate governs requests to ``url``.

    ``https`` is itself. ``http`` inside the cluster is None: there is no
    certificate. An operator-typed ``http://`` is asked once where it
    redirects; the appliance frontend sends it to ``https://``, and that is
    the certificate to pin. A failed probe is not remembered, so it is asked
    again next time rather than caching an outage as "no TLS".
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme == "https":
        return url
    if scheme != "http" or _in_cluster(parts.hostname or ""):
        return None
    if url in _redirects:
        return _redirects[url]
    try:
        resp = httpx.get(url.rstrip("/") + "/", follow_redirects=False, timeout=_CONNECT_TIMEOUT_S)
    except httpx.HTTPError:
        return None
    location = resp.headers.get("location", "") if resp.is_redirect else ""
    target = location if location.lower().startswith("https://") else None
    _redirects[url] = target
    return target


# ── the client every control-plane call uses ─────────────────────────────────


def skip_verify() -> bool:
    return os.environ.get("SPATIUM_INSECURE_SKIP_TLS_VERIFY", "").lower() in ("1", "true", "yes")


def client(
    state_dir: Path, url: str, *, first_contact: bool = True, **kwargs: Any
) -> httpx.Client:
    """An ``httpx.Client`` for the control plane at ``url``, verifying it.

    With ``first_contact`` (registration) it pins the presented certificate
    when nothing is pinned yet. Without it (the proxy loops), an unpinned
    supervisor gets ordinary system-CA verification, which a self-signed
    control plane fails, so those loops wait for registration to take the
    pin rather than taking it themselves.

    An ``http://`` URL whose server redirects to ``https://`` is not sent
    over http at all: requests for that origin go straight to the pinned
    ``https://`` target. Following the redirect instead would put the body
    (the pairing code on register, the session token on every heartbeat) on
    the wire in cleartext before the 301, and httpx would also turn the
    redirected POST into a GET.
    """
    kwargs.setdefault("follow_redirects", True)
    if skip_verify():
        if not _state["skip_warned"]:
            _state["skip_warned"] = True
            log.warning(
                "supervisor.tls_verify_disabled",
                reason="SPATIUM_INSECURE_SKIP_TLS_VERIFY=1",
                hint=(
                    "Control-plane TLS verification is OFF for this supervisor: "
                    "anyone on the network path can read the agent keys it "
                    "receives and serve it an upgrade image. Unset it; the "
                    "supervisor pins the control plane's certificate itself."
                ),
            )
        return httpx.Client(verify=False, **kwargs)
    target = tls_url(url)
    if target is None:
        return httpx.Client(**kwargs)
    pins = load_pins(state_dir)
    if pins is None:
        if not first_contact:
            return httpx.Client(**kwargs)
        pins = _pin_first_contact(state_dir, target)
    if urlsplit(url).scheme.lower() == "http":
        transport = _UpgradeToHttps(
            httpx.HTTPTransport(verify=pinned_context(pins)), httpx.URL(url), httpx.URL(target)
        )
        return httpx.Client(transport=transport, **kwargs)
    return httpx.Client(verify=pinned_context(pins), **kwargs)


class _UpgradeToHttps(httpx.BaseTransport):
    """Send requests for an ``http://`` origin to its ``https://`` target."""

    def __init__(self, inner: httpx.BaseTransport, src: httpx.URL, dst: httpx.URL) -> None:
        self._inner = inner
        self._src = (src.host, src.port)
        self._dst = dst

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http" and (request.url.host, request.url.port) == self._src:
            request.url = request.url.copy_with(
                scheme="https", host=self._dst.host, port=self._dst.port
            )
            request.headers["Host"] = self._dst.netloc.decode("ascii")
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


def _pin_first_contact(state_dir: Path, target: str) -> str:
    with _lock:
        pins = load_pins(state_dir)
        if pins is not None:  # another thread got here first
            return pins
        presented = presented_leaf_pem(target)
        _save_pins(state_dir, presented)
    log.warning(
        "supervisor.tls.pinned_on_first_contact",
        url=_origin(target),
        sha256=display_fingerprint(cert_sha256(presented)),
        detail=(
            "Trusting this certificate from now on. It should match the "
            "fingerprint shown under Appliance -> TLS on the control plane; if "
            "it does not, something intercepted this connection."
        ),
    )
    return presented


# ── rotation, through the appliance CA ───────────────────────────────────────


def is_verification_failure(exc: BaseException) -> bool:
    """Whether ``exc`` (or anything it wraps) is a certificate verify failure."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ssl.SSLCertVerificationError):
            return True
        if "CERTIFICATE_VERIFY_FAILED" in str(cur):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _load_ca(state_dir: Path) -> str | None:
    try:
        pem = (state_dir / "tls" / CA_CHAIN_FILENAME).read_text(encoding="ascii")
    except OSError:
        return None
    return pem if "BEGIN CERTIFICATE" in pem else None


def verify_pin_set(body: dict[str, Any], ca_pem: str, *, now: datetime | None = None) -> set[str]:
    """The certificate fingerprints a signed list vouches for.

    Raises :class:`PinSetError` unless the signature verifies against the
    appliance CA and the list is recent.
    """
    if body.get("algorithm") != PIN_SET_ALGORITHM:
        raise PinSetError(f"unexpected algorithm {body.get('algorithm')!r}")
    try:
        payload = base64.b64decode(body["payload"], validate=True)
        signature = base64.b64decode(body["signature"], validate=True)
    except (KeyError, ValueError) as exc:
        raise PinSetError(f"malformed signed list: {exc}") from exc
    ca_key = _certs(ca_pem)[0].public_key()
    if not isinstance(ca_key, rsa.RSAPublicKey):
        raise PinSetError("the appliance CA certificate does not hold an RSA key")
    try:
        ca_key.verify(signature, payload, _PSS, hashes.SHA256())
    except InvalidSignature as exc:
        raise PinSetError("the signature does not verify against the appliance CA") from exc
    try:
        data = json.loads(payload)
        issued = datetime.fromisoformat(data["issued_at"])
        vouched = {str(fp).lower() for fp in data["certs_sha256"]}
    except (ValueError, KeyError, TypeError) as exc:
        raise PinSetError(f"unreadable signed list: {exc}") from exc
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=UTC)
    if abs((now or datetime.now(UTC)) - issued) > PIN_SET_MAX_AGE:
        raise PinSetError(f"the signed list was issued at {issued.isoformat()}, too long ago")
    return vouched


def _fetch_vouched(target: str, trust_pem: str, ca_pem: str) -> set[str]:
    """Fetch the signed list over a connection pinned to ``trust_pem``."""
    with httpx.Client(verify=pinned_context(trust_pem), timeout=_CONNECT_TIMEOUT_S) as c:
        resp = c.get(_origin(target) + PIN_SET_PATH)
    if resp.status_code >= 500:
        raise PinSetUnavailable(f"the control plane answered HTTP {resp.status_code}")
    if resp.status_code != 200:
        raise PinSetError(f"the control plane answered HTTP {resp.status_code}")
    try:
        body = resp.json()
    except ValueError as exc:
        raise PinSetError("the signed list is not JSON") from exc
    return verify_pin_set(body, ca_pem)


def try_repin(state_dir: Path, url: str) -> bool:
    """After a verification failure: adopt the new certificate if the CA
    vouches for it. Returns True when the pin changed."""
    if skip_verify():
        return False
    target = tls_url(url)
    if target is None:
        return False
    with _lock:
        old = load_pins(state_dir)
        try:
            presented = presented_leaf_pem(target)
        except (OSError, ssl.SSLError) as exc:
            log.warning("supervisor.tls.repin_unreachable", error=str(exc))
            return False
        new_fp = cert_sha256(presented)
        if old is not None and new_fp in _pinned_fingerprints(old):
            # Same certificate: the failure was something else. Say so, or a
            # pinned certificate that has EXPIRED leaves the supervisor offline
            # with nothing but a generic heartbeat failure in its log.
            log.error(
                "supervisor.tls.pinned_certificate_rejected",
                sha256=display_fingerprint(new_fp),
                detail=(
                    "The control plane presents the pinned certificate, yet the "
                    "handshake still fails verification: most likely it has "
                    "expired. Renew or replace it under Appliance -> TLS."
                ),
            )
            return False
        ca_pem = _load_ca(state_dir)
        if ca_pem is None:
            # Not approved yet, so there is no authority to ask, and nothing
            # the control plane holds back from an unapproved node has flowed.
            _save_pins(state_dir, presented)
            log.warning(
                "supervisor.tls.repinned_before_approval",
                sha256=display_fingerprint(new_fp),
            )
            return True
        try:
            vouched = _fetch_vouched(target, presented, ca_pem)
        except (PinSetError, httpx.HTTPError) as exc:
            log.error(
                "supervisor.tls.repin_refused",
                presented=display_fingerprint(new_fp),
                reason=str(exc),
            )
            return False
        if new_fp not in vouched:
            log.error(
                "supervisor.tls.certificate_not_vouched",
                presented=display_fingerprint(new_fp),
                vouched=[display_fingerprint(fp) for fp in sorted(vouched)],
                detail=(
                    "The control plane is presenting a certificate its own CA "
                    "does not vouch for: an interception, or a certificate the "
                    "control plane has not recorded. Keeping the old pin."
                ),
            )
            return False
        _save_pins(state_dir, presented)
    log.info(
        "supervisor.tls.repinned",
        old=display_fingerprint(cert_sha256(old)) if old else None,
        new=display_fingerprint(new_fp),
    )
    return True


def check_pin_vouched_once(state_dir: Path, url: str) -> None:
    """Once per process, after approval: is the first-contact pin one the CA
    vouches for? Catches an interception that was present at pairing (unless
    it also replaced the CA). Retried on a transient failure."""
    if _state["vouch_checked"] or skip_verify():
        return
    target = tls_url(url)
    pins = load_pins(state_dir)
    ca_pem = _load_ca(state_dir)
    if target is None or pins is None or ca_pem is None:
        return
    try:
        vouched = _fetch_vouched(target, pins, ca_pem)
    except (httpx.HTTPError, PinSetUnavailable):
        return  # transient: try again next loop
    except PinSetError as exc:
        _state["vouch_checked"] = True
        log.error("supervisor.tls.pin_unverifiable", reason=str(exc))
        return
    _state["vouch_checked"] = True
    pinned = _pinned_fingerprints(pins)
    if pinned & vouched:
        log.info(
            "supervisor.tls.pin_vouched",
            sha256=[display_fingerprint(fp) for fp in sorted(pinned & vouched)],
        )
        return
    log.error(
        "supervisor.tls.pin_not_vouched",
        pinned=[display_fingerprint(fp) for fp in sorted(pinned)],
        vouched=[display_fingerprint(fp) for fp in sorted(vouched)],
        detail=(
            "The certificate this supervisor pinned when it first contacted the "
            "control plane is not one the control plane's CA vouches for. "
            "Either something intercepted the first contact, or the certificate "
            "has changed since; compare with Appliance -> TLS on the control plane."
        ),
    )
