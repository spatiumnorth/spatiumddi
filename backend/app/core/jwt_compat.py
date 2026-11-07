"""HS256 JWT encode/decode on joserfc, behaviour-compatible with python-jose.

python-jose is unmaintained and dragged ecdsa / rsa in with it, so
every JWT this control plane signs (access tokens, the three agent tokens,
the OIDC/SAML flow cookie) now goes through joserfc, which the OIDC ID-token
path already used. The two libraries must agree on the wire, or an upgrade
logs everybody out and every agent re-bootstraps:

* Encoding: same compact JWS, ``{"alg":"HS256","typ":"JWT"}`` header, claims
  as compact JSON, ``exp`` / ``iat`` / ``nbf`` given as ``datetime`` become
  integer epoch seconds (python-jose did the same).
* Decoding: signature checked against the pinned ``algorithms`` (so ``none``
  and an RS256 header are refused), then python-jose's default claim checks
  with leeway 0: ``exp`` (``exp < now`` expired), ``nbf`` (``nbf > now``
  refused), ``iat`` (must be numeric; a future ``iat`` is NOT refused), ``sub``
  and ``jti`` must be strings, and ``aud`` — verified by default — means a token
  carrying ``aud`` is refused because no caller names an audience.
* Every failure raises :class:`JWTError`, the one name callers catch to answer
  401 / re-bootstrap.

joserfc only *warns* (``SecurityWarning``) on an HMAC key under 112 bits; it
does not refuse, so a short operator ``SECRET_KEY`` keeps working exactly as it
did under python-jose. The warning is silenced here because the secret-key
hardening check at startup already reports a weak key.
"""

from __future__ import annotations

import calendar
import json
import warnings
from datetime import UTC, datetime
from typing import Any

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import OctKey

ALGORITHM = "HS256"


class JWTError(Exception):
    """Any failure to verify or parse a JWT (the old ``jose.JWTError``)."""


def _key(secret: str) -> OctKey:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return OctKey.import_key(secret)


def encode(claims: dict[str, Any], secret: str, algorithm: str = ALGORITHM) -> str:
    """Sign ``claims`` as an HS256 JWT. ``datetime`` exp/iat/nbf become ints."""
    if algorithm != ALGORITHM:
        raise JWTError(f"Unsupported algorithm {algorithm}")
    payload = dict(claims)
    for name in ("exp", "iat", "nbf"):
        value = payload.get(name)
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=UTC)
            payload[name] = calendar.timegm(value.utctimetuple())
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return jws.serialize_compact({"alg": ALGORITHM, "typ": "JWT"}, body, _key(secret))


def _int_claim(claims: dict[str, Any], name: str) -> int | None:
    if name not in claims:
        return None
    value = claims[name]
    # python-jose ran int() on it; bool / None / list are not numbers.
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise JWTError(f"Claim {name} must be an integer.")
    try:
        return int(value)
    except ValueError as exc:
        raise JWTError(f"Claim {name} must be an integer.") from exc


def decode(token: str, secret: str, algorithms: list[str] | None = None) -> dict[str, Any]:
    """Verify the signature and python-jose's default claims; return the claims."""
    algs = list(algorithms) if algorithms else [ALGORITHM]
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            obj = jws.deserialize_compact(token, _key(secret), algorithms=algs)
        claims = json.loads(obj.payload)
    except (JoseError, ValueError, TypeError, AttributeError) as exc:
        raise JWTError(f"Invalid token: {exc}") from exc
    if not isinstance(claims, dict):
        raise JWTError("Invalid claims string: must be a json object")

    now = calendar.timegm(datetime.now(UTC).utctimetuple())
    _int_claim(claims, "iat")
    nbf = _int_claim(claims, "nbf")
    if nbf is not None and nbf > now:
        raise JWTError("The token is not yet valid (nbf)")
    exp = _int_claim(claims, "exp")
    if exp is not None and exp < now:
        raise JWTError("Signature has expired.")
    if "aud" in claims:
        aud = claims["aud"]
        auds = [aud] if isinstance(aud, str) else aud
        if not isinstance(auds, list) or any(not isinstance(a, str) for a in auds):
            raise JWTError("Invalid claim format in token")
        raise JWTError("Invalid audience")
    if "sub" in claims and not isinstance(claims["sub"], str):
        raise JWTError("Subject must be a string.")
    if "jti" in claims and not isinstance(claims["jti"], str):
        raise JWTError("JWT ID must be a string.")
    return claims
