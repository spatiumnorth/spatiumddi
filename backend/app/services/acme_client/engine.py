"""Minimal RFC 8555 ACME client — hand-rolled (issue #438 Phase 1).

No ``acme`` / ``certbot`` dependency: just ``cryptography`` for keys +
CSR + signing, ``httpx`` for async HTTP to the CA, and a manual JWS
encoder. This keeps the dependency surface to libraries already in
``backend/pyproject.toml``.

What this module owns (pure ACME protocol, no DB, no DNS-write
knowledge):

* directory fetch + ``newNonce`` priming;
* ``newAccount`` (with optional External Account Binding) + account-URL
  caching, exposed as :meth:`ACMEClient.ensure_account`;
* ``newOrder`` with ``dns`` identifiers;
* authorization fetch + ``dns-01`` challenge selection;
* the RFC 7638 JWK thumbprint → key authorization → TXT value
  computation (:meth:`ACMEClient.get_dns01_challenge`);
* "respond / tell-ready" POST to the challenge URL;
* authorization + order polling;
* ``finalize`` with a DER CSR;
* certificate download (full PEM chain).

The two load-bearing RFC details:

* **Replay-Nonce.** Every response (success or error) carries a
  ``Replay-Nonce`` header; we stash it and use it on the *next* request.
  We prime the pump with ``newNonce`` and refresh on ``badNonce``.
* **JWS protected header.** ``jwk`` is sent ONLY on ``newAccount`` (and
  ``revokeCert`` with the cert key, not used here). Every other request
  is keyed by ``kid`` (the CA-assigned account URL). ``alg`` matches the
  account key type (RS256 for RSA, ES256/ES384 for EC).

All requests use the JWS "POST-as-GET" pattern where the payload is the
empty string for reads.

Callers drive the flow from
:mod:`app.services.acme_client.orchestrator`; the DNS-01 TXT write lives
in :mod:`app.services.acme_client.dns01`.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

import httpx
import structlog
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

logger = structlog.get_logger(__name__)

# CA directory URLs. Staging issues untrusted certs but has far higher
# rate limits — the UI defaults issuance attempts here until an operator
# explicitly flips to production.
LE_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
LE_PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"

# Polling caps. The CA validates a dns-01 challenge within seconds once
# signalled, but can lag under load; finalize is usually instant.
_AUTHZ_POLL_INTERVAL = 3.0
_AUTHZ_POLL_TIMEOUT = 180.0
_ORDER_POLL_INTERVAL = 2.0
_ORDER_POLL_TIMEOUT = 120.0

_JOSE_CONTENT_TYPE = "application/jose+json"
_HTTP_TIMEOUT = 30.0


class ACMEProtocolError(Exception):
    """Any non-recoverable failure talking to the CA.

    Carries the ACME problem document (``type`` / ``detail``) when the
    CA returned one, so the orchestrator can persist a useful
    ``last_error``.
    """

    def __init__(self, message: str, *, problem: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.problem = problem or {}


# ── base64url helpers (no padding, per JOSE) ────────────────────────


def generate_account_key_pem() -> str:
    """A fresh EC-P256 ACME account key, PKCS#8 PEM, unencrypted (the
    caller Fernet-wraps it for storage)."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


# ── JWK + thumbprint (RFC 7517 / 7638) ──────────────────────────────


def _public_jwk(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> dict[str, str]:
    """Build the public JWK for the account key.

    Member ordering doesn't matter for the ``jwk`` header, but the
    thumbprint (:func:`_jwk_thumbprint`) re-serialises with sorted keys
    per RFC 7638, so this dict is only the wire representation.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        rsa_numbers = key.public_key().public_numbers()
        n_len = (rsa_numbers.n.bit_length() + 7) // 8
        e_len = (rsa_numbers.e.bit_length() + 7) // 8
        return {
            "kty": "RSA",
            "n": b64url(_int_to_bytes(rsa_numbers.n, n_len)),
            "e": b64url(_int_to_bytes(rsa_numbers.e, e_len)),
        }
    # EC
    ec_numbers = key.public_key().public_numbers()
    crv, coord_len = _ec_curve_params(key.curve)
    return {
        "kty": "EC",
        "crv": crv,
        "x": b64url(_int_to_bytes(ec_numbers.x, coord_len)),
        "y": b64url(_int_to_bytes(ec_numbers.y, coord_len)),
    }


def _ec_curve_params(curve: ec.EllipticCurve) -> tuple[str, int]:
    if isinstance(curve, ec.SECP256R1):
        return "P-256", 32
    if isinstance(curve, ec.SECP384R1):
        return "P-384", 48
    if isinstance(curve, ec.SECP521R1):
        return "P-521", 66
    raise ACMEProtocolError(f"unsupported EC curve for ACME account key: {curve.name}")


def _jwk_thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 SHA-256 JWK thumbprint, base64url-encoded.

    The thumbprint is over the JWK's *required* members only, with keys
    sorted lexicographically and no whitespace.
    """
    if jwk["kty"] == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:  # EC
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("ascii")
    return b64url(hashlib.sha256(canonical).digest())


def _alg_for_key(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    crv, _ = _ec_curve_params(key.curve)
    return {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}[crv]


def _sign_jws(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    signing_input: bytes,
) -> bytes:
    """Sign the ``base64url(protected).base64url(payload)`` input.

    RSA → RS256 (PKCS1v15 + SHA-256). EC → ES256/384/512 with the
    signature in the JOSE fixed-width R||S concatenation (NOT DER).
    """
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    # EC: cryptography returns DER; JOSE wants raw R||S.
    crv, coord_len = _ec_curve_params(key.curve)
    hash_alg = {"P-256": hashes.SHA256(), "P-384": hashes.SHA384(), "P-521": hashes.SHA512()}[crv]
    der_sig = key.sign(signing_input, ec.ECDSA(hash_alg))
    r, s = decode_dss_signature(der_sig)
    return _int_to_bytes(r, coord_len) + _int_to_bytes(s, coord_len)


# ── Parsed-challenge dataclass ──────────────────────────────────────


@dataclass(frozen=True)
class DNS01Challenge:
    """The dns-01 challenge selected from an authorization.

    ``identifier`` is the bare domain being validated (e.g.
    ``example.com``); the orchestrator turns it into the
    ``_acme-challenge.<identifier>`` FQDN. ``url`` is the challenge
    resource the client POSTs to signal readiness.
    """

    identifier: str
    url: str
    token: str
    status: str


# ── The client ──────────────────────────────────────────────────────


class ACMEClient:
    """Stateful per-issuance RFC 8555 client.

    One instance drives one order. Construct with the directory URL +
    the account key PEM (the orchestrator decrypts it from
    :class:`~app.models.acme_client.ACMEClientAccount`). Optionally pass
    a cached ``account_url`` (``kid``) to skip a redundant ``newAccount``
    side effect — though ``newAccount`` is idempotent at the CA, so
    re-running it just returns the same account.

    Use as an async context manager so the underlying ``httpx`` client
    is closed::

        async with ACMEClient(directory_url, account_key_pem) as client:
            await client.ensure_account(email="ops@example.com")
            order = await client.new_order(["example.com"])
            ...
    """

    def __init__(
        self,
        directory_url: str,
        account_key_pem: str,
        *,
        account_url: str | None = None,
        eab_kid: str | None = None,
        eab_hmac_b64: str | None = None,
    ) -> None:
        self.directory_url = directory_url
        self._key = self._load_key(account_key_pem)
        self._jwk = _public_jwk(self._key)
        self._alg = _alg_for_key(self._key)
        self.account_url = account_url
        self._eab_kid = eab_kid
        self._eab_hmac_b64 = eab_hmac_b64
        self._directory: dict[str, Any] | None = None
        self._nonce: str | None = None
        self._http = httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT,
            headers={"User-Agent": "spatiumddi-acme-client/1 (+https://www.spatiumddi.com)"},
        )

    async def __aenter__(self) -> ACMEClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    @staticmethod
    def _load_key(pem: str) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        try:
            key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        except (ValueError, TypeError) as exc:
            raise ACMEProtocolError(f"account key parse failed: {exc}") from exc
        if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise ACMEProtocolError(
                f"unsupported account key type {type(key).__name__} — use RSA or EC"
            )
        return key

    # ── Directory + nonce plumbing ──────────────────────────────────

    async def _get_directory(self) -> dict[str, Any]:
        if self._directory is None:
            resp = await self._http.get(self.directory_url)
            if resp.status_code != 200:
                raise ACMEProtocolError(
                    f"directory fetch failed: HTTP {resp.status_code}",
                )
            self._directory = resp.json()
        return self._directory

    async def _ensure_nonce(self) -> str:
        if self._nonce is None:
            directory = await self._get_directory()
            new_nonce_url = directory["newNonce"]
            resp = await self._http.head(new_nonce_url)
            nonce = resp.headers.get("Replay-Nonce")
            if not nonce:
                # Some CAs only return the nonce on GET; retry.
                resp = await self._http.get(new_nonce_url)
                nonce = resp.headers.get("Replay-Nonce")
            if not nonce:
                raise ACMEProtocolError("CA did not return a Replay-Nonce on newNonce")
            self._nonce = nonce
        return self._nonce

    def _stash_nonce(self, resp: httpx.Response) -> None:
        nonce = resp.headers.get("Replay-Nonce")
        if nonce:
            self._nonce = nonce

    # ── Signed request core ─────────────────────────────────────────

    def _build_jws(self, url: str, payload: Any, nonce: str) -> bytes:
        """Encode + sign one JWS request body.

        ``payload`` of ``None`` produces the empty-string payload of a
        POST-as-GET read; a dict is JSON-serialised; ``b""`` / ``""`` is
        also treated as the read sentinel.
        """
        protected: dict[str, Any] = {"alg": self._alg, "nonce": nonce, "url": url}
        if self.account_url is None:
            # Pre-account (newAccount) — identify by full JWK.
            protected["jwk"] = self._jwk
        else:
            protected["kid"] = self.account_url

        protected_b64 = b64url(json.dumps(protected, separators=(",", ":")).encode("utf-8"))
        if payload is None or payload == "" or payload == b"":
            payload_b64 = ""
        else:
            payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = _sign_jws(self._key, signing_input)
        body = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64url(signature),
        }
        return json.dumps(body).encode("utf-8")

    async def _post(self, url: str, payload: Any, *, _retried: bool = False) -> httpx.Response:
        """POST a signed JWS, replaying / refreshing the nonce.

        On ``badNonce`` we refresh the nonce once and retry — the RFC
        explicitly allows this and it's common under concurrency.
        """
        nonce = await self._ensure_nonce()
        body = self._build_jws(url, payload, nonce)
        resp = await self._http.post(
            url, content=body, headers={"Content-Type": _JOSE_CONTENT_TYPE}
        )
        self._stash_nonce(resp)

        if resp.status_code >= 400:
            problem = self._parse_problem(resp)
            if (
                not _retried
                and problem.get("type", "").endswith("badNonce")
                and self._nonce is not None
            ):
                return await self._post(url, payload, _retried=True)
            raise ACMEProtocolError(
                f"ACME {url} → HTTP {resp.status_code}: "
                f"{problem.get('detail') or problem.get('type') or resp.text[:300]}",
                problem=problem,
            )
        return resp

    @staticmethod
    def _parse_problem(resp: httpx.Response) -> dict[str, Any]:
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    # ── Account ─────────────────────────────────────────────────────

    async def ensure_account(self, *, email: str | None = None) -> str:
        """Create-or-locate the ACME account; return the account URL.

        ``newAccount`` is idempotent: with ``onlyReturnExisting`` unset
        the CA either creates the account or returns the existing one
        bound to this key. We cache the returned URL on ``self`` (the
        ``kid`` for every subsequent request) and return it so the
        orchestrator can persist it.

        If we already hold a cached ``account_url`` (a re-issue / renewal
        against a previously-registered account) we MUST NOT re-POST
        ``newAccount``: ``_build_jws`` signs with ``kid`` once
        ``account_url`` is set, but RFC 8555 §6.2 requires ``newAccount``
        to be signed with the embedded ``jwk`` — a ``kid``-keyed
        ``newAccount`` is rejected by the CA. The account is idempotent
        and already known, so just reuse the cached URL.
        """
        if self.account_url is not None:
            return self.account_url
        directory = await self._get_directory()
        payload: dict[str, Any] = {"termsOfServiceAgreed": True}
        if email:
            payload["contact"] = [f"mailto:{email}"]
        if self._eab_kid and self._eab_hmac_b64:
            payload["externalAccountBinding"] = self._build_eab(directory["newAccount"])

        resp = await self._post(directory["newAccount"], payload)
        account_url = resp.headers.get("Location")
        if not account_url:
            raise ACMEProtocolError("newAccount response missing Location header")
        self.account_url = account_url
        logger.info("acme_client_account_ready", account_url=account_url, has_email=bool(email))
        return account_url

    def _build_eab(self, new_account_url: str) -> dict[str, str]:
        """RFC 8555 §7.3.4 External Account Binding inner JWS.

        The inner JWS is signed with the EAB HMAC key (HS256), payload =
        the account public JWK, protected = ``{alg, kid, url}``.
        """
        import hmac

        if self._eab_hmac_b64 is None or self._eab_kid is None:
            raise ACMEProtocolError("EAB requested but eab_kid/eab_hmac not configured")
        hmac_key = base64.urlsafe_b64decode(
            self._eab_hmac_b64 + "=" * (-len(self._eab_hmac_b64) % 4)
        )
        protected = {"alg": "HS256", "kid": self._eab_kid, "url": new_account_url}
        protected_b64 = b64url(json.dumps(protected, separators=(",", ":")).encode("utf-8"))
        payload_b64 = b64url(json.dumps(self._jwk, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        sig = hmac.new(hmac_key, signing_input, hashlib.sha256).digest()
        return {"protected": protected_b64, "payload": payload_b64, "signature": b64url(sig)}

    # ── Order ───────────────────────────────────────────────────────

    async def new_order(self, domains: list[str]) -> dict[str, Any]:
        """Create a newOrder for ``domains`` (all ``dns`` identifiers).

        Returns a dict augmented with ``url`` (the order URL from the
        ``Location`` header) since the order body itself doesn't carry
        its own URL.
        """
        if self.account_url is None:
            raise ACMEProtocolError("ensure_account must run before new_order")
        directory = await self._get_directory()
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        resp = await self._post(directory["newOrder"], payload)
        order = resp.json()
        order["url"] = resp.headers.get("Location") or order.get("url")
        if not order.get("url"):
            raise ACMEProtocolError("newOrder response missing order URL (Location header)")
        return order

    async def get_order(self, order_url: str) -> dict[str, Any]:
        resp = await self._post(order_url, None)
        order = resp.json()
        order.setdefault("url", order_url)
        return order

    async def get_authorizations(self, order: dict[str, Any]) -> list[dict[str, Any]]:
        """Fetch every authorization object referenced by the order."""
        authzs: list[dict[str, Any]] = []
        for authz_url in order.get("authorizations", []):
            resp = await self._post(authz_url, None)
            authz = resp.json()
            authz["url"] = authz_url
            authzs.append(authz)
        return authzs

    # ── dns-01 challenge ────────────────────────────────────────────

    def get_dns01_challenge(self, authz: dict[str, Any]) -> tuple[DNS01Challenge, str, str]:
        """Pick the dns-01 challenge from an authorization.

        Returns ``(challenge, key_authorization, txt_value)`` where:

        * ``key_authorization`` = ``token + "." + base64url(thumbprint)``
          (the value the CA expects the client to "know");
        * ``txt_value`` = ``base64url(sha256(key_authorization))`` — the
          string that goes into the ``_acme-challenge`` TXT record.

        Raises :class:`ACMEProtocolError` if the authorization offers no
        dns-01 challenge.
        """
        identifier = authz.get("identifier", {}).get("value", "")
        for ch in authz.get("challenges", []):
            if ch.get("type") == "dns-01":
                challenge = DNS01Challenge(
                    identifier=identifier,
                    url=ch["url"],
                    token=ch["token"],
                    status=ch.get("status", "pending"),
                )
                key_authorization = f"{ch['token']}.{_jwk_thumbprint(self._jwk)}"
                txt_value = b64url(hashlib.sha256(key_authorization.encode("ascii")).digest())
                return challenge, key_authorization, txt_value
        raise ACMEProtocolError(f"authorization for {identifier!r} offers no dns-01 challenge")

    def get_http01_challenge(self, authz: dict[str, Any]) -> tuple[DNS01Challenge, str]:
        """Pick the http-01 challenge from an authorization (#438 Phase 4).

        Returns ``(challenge, key_authorization)``. Unlike dns-01, the
        key-authorization is served *verbatim* at
        ``/.well-known/acme-challenge/<token>`` — there's no sha256/TXT
        transform. (Reuses :class:`DNS01Challenge` as a neutral challenge
        carrier; the ``identifier``/``url``/``token`` fields apply to both.)
        """
        identifier = authz.get("identifier", {}).get("value", "")
        for ch in authz.get("challenges", []):
            if ch.get("type") == "http-01":
                challenge = DNS01Challenge(
                    identifier=identifier,
                    url=ch["url"],
                    token=ch["token"],
                    status=ch.get("status", "pending"),
                )
                key_authorization = f"{ch['token']}.{_jwk_thumbprint(self._jwk)}"
                return challenge, key_authorization
        raise ACMEProtocolError(f"authorization for {identifier!r} offers no http-01 challenge")

    async def tell_ready(self, challenge_url: str) -> dict[str, Any]:
        """Signal the CA the dns-01 challenge is ready to validate.

        RFC 8555 §7.5.1: POST the challenge URL with an empty JSON
        object ``{}`` payload (NOT POST-as-GET).
        """
        resp = await self._post(challenge_url, {})
        return resp.json()

    # ── Polling ─────────────────────────────────────────────────────

    async def poll_authorization(
        self,
        authz_url: str,
        *,
        timeout: float = _AUTHZ_POLL_TIMEOUT,
        interval: float = _AUTHZ_POLL_INTERVAL,
    ) -> dict[str, Any]:
        """Poll an authorization until ``valid`` / ``invalid`` / timeout.

        Raises :class:`ACMEProtocolError` on ``invalid`` (carrying the
        failing challenge's problem document) or timeout.
        """
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            resp = await self._post(authz_url, None)
            authz = resp.json()
            status = authz.get("status")
            if status == "valid":
                return authz
            if status == "invalid":
                problem = self._authz_problem(authz)
                raise ACMEProtocolError(
                    f"authorization {authz_url} became invalid: "
                    f"{problem.get('detail') or problem.get('type') or 'no detail'}",
                    problem=problem,
                )
            if asyncio.get_running_loop().time() >= deadline:
                raise ACMEProtocolError(
                    f"authorization {authz_url} did not validate within {timeout:.0f}s "
                    f"(last status: {status})"
                )
            await asyncio.sleep(interval)

    @staticmethod
    def _authz_problem(authz: dict[str, Any]) -> dict[str, Any]:
        for ch in authz.get("challenges", []):
            if ch.get("type") == "dns-01" and ch.get("error"):
                return ch["error"]
        for ch in authz.get("challenges", []):
            if ch.get("error"):
                return ch["error"]
        return {}

    async def poll_order(
        self,
        order_url: str,
        *,
        until: tuple[str, ...] = ("ready", "valid"),
        timeout: float = _ORDER_POLL_TIMEOUT,
        interval: float = _ORDER_POLL_INTERVAL,
    ) -> dict[str, Any]:
        """Poll an order until its status is in ``until`` (or invalid / timeout)."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            order = await self.get_order(order_url)
            status = order.get("status")
            if status in until:
                return order
            if status == "invalid":
                err = order.get("error")
                problem = err if isinstance(err, dict) else {}
                raise ACMEProtocolError(
                    f"order {order_url} became invalid: "
                    f"{problem.get('detail') or problem.get('type') or 'no detail'}",
                    problem=problem,
                )
            if asyncio.get_running_loop().time() >= deadline:
                raise ACMEProtocolError(
                    f"order {order_url} did not reach {until} within {timeout:.0f}s "
                    f"(last status: {status})"
                )
            await asyncio.sleep(interval)

    # ── Finalize + download ─────────────────────────────────────────

    async def finalize(self, order: dict[str, Any], csr_der: bytes) -> dict[str, Any]:
        """Submit the DER CSR to the order's finalize URL.

        Returns the (possibly still ``processing``) order body; the
        orchestrator then polls to ``valid`` and downloads.
        """
        finalize_url = order.get("finalize")
        if not finalize_url:
            raise ACMEProtocolError("order has no finalize URL")
        payload = {"csr": b64url(csr_der)}
        resp = await self._post(finalize_url, payload)
        body = resp.json()
        body.setdefault("url", order.get("url"))
        return body

    async def download_certificate(self, order: dict[str, Any]) -> str:
        """Download the issued cert chain (full PEM) from the order.

        Requires the order to be ``valid`` with a ``certificate`` URL.
        Returns the leaf + intermediates as a single PEM string ready
        for ``ApplianceCertificate.cert_pem``.
        """
        cert_url = order.get("certificate")
        if not cert_url:
            raise ACMEProtocolError("order is valid but carries no certificate URL")
        # The CA returns PEM (application/pem-certificate-chain) as the
        # response body of a POST-as-GET.
        resp = await self._post(cert_url, None)
        return resp.text


__all__ = [
    "ACMEClient",
    "ACMEProtocolError",
    "DNS01Challenge",
    "LE_PRODUCTION_DIRECTORY",
    "LE_STAGING_DIRECTORY",
    "b64url",
]
