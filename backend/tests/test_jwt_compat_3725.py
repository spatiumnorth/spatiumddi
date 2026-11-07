"""python-jose -> joserfc migration (#3725): tokens minted by the old code
must still verify, and everything the old code refused must still be refused
with the one ``JWTError`` the callers turn into 401 / agent re-bootstrap.

The hard-coded tokens below were produced by python-jose 3.5.0
(``jwt.encode(claims, SECRET, algorithm="HS256")``)."""

import base64
import hashlib
import hmac
import json
import uuid

import pytest

from app.core import jwt_compat
from app.core.jwt_compat import JWTError
from app.core.security import create_access_token, decode_access_token
from app.services.dhcp import agent_token as dhcp_tok
from app.services.dns import agent_token as dns_tok
from app.services.looking_glass import agent_token as lg_tok

SECRET = "fixed-secret-for-3725-tests"
FAR = 4102444800

ACCESS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEiLCJleHAiOjQxMDI0NDQ4MDAsInR5cGUiOiJhY2Nlc3MiLCJqdGkiOiIyMjIyMjIyMi0yMjIyLTIyMjItMjIyMi0yMjIyMjIyMjIyMjIifQ.xBUIriwjHex-25OVTBivds60wGj_-lZygOlEn4ol5Dc"
ACCESS_CLAIMS = {
    "sub": "11111111-1111-1111-1111-111111111111",
    "exp": FAR,
    "type": "access",
    "jti": "22222222-2222-2222-2222-222222222222",
}
DNS_AGENT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcnYtMSIsImFnZW50X2lkIjoiYTEiLCJmaW5nZXJwcmludCI6ImZmIiwidHlwIjoiZG5zX2FnZW50IiwiZXhwIjo0MTAyNDQ0ODAwLCJqdGkiOiJhYmMifQ.HjLLsKa9xzwEEx5v0V_80P313I8jKMBSm1-0cqM7LCc"
DNS_AGENT_CLAIMS = {
    "sub": "srv-1",
    "agent_id": "a1",
    "fingerprint": "ff",
    "typ": "dns_agent",
    "exp": FAR,
    "jti": "abc",
}
EXPIRED = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4IiwiZXhwIjoxNjAwMDAwMDAwLCJ0eXBlIjoiYWNjZXNzIiwianRpIjoiaiJ9.VuMbJgMrkKdGjy57WmA7pf9skB6NcOxVi5QQm0VDB2U"
FUTURE_NBF = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4IiwiZXhwIjo0MTAyNDQ0ODAwLCJuYmYiOjQxMDI0NDQ3OTksInR5cGUiOiJhY2Nlc3MiLCJqdGkiOiJqIn0.xHUm4uwN3qd-jG11El0Mv3a171JhUDeh9o48Z-PEB6M"
FUTURE_IAT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4IiwiZXhwIjo0MTAyNDQ0ODAwLCJpYXQiOjQxMDI0NDQ3OTksInR5cGUiOiJhY2Nlc3MiLCJqdGkiOiJqIn0.dDhpRVsenwOq6EJlvIH1hnpp70BqCx8xoNxS6D3xVKI"
WITH_AUD = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4IiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJzb21lb25lIiwidHlwZSI6ImFjY2VzcyIsImp0aSI6ImoifQ.495GETaH2Zwah40TXB-WsVaX32DtqIUOcnbI5OAutLk"
INT_SUB = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjUsImV4cCI6NDEwMjQ0NDgwMCwidHlwZSI6ImFjY2VzcyIsImp0aSI6ImoifQ.ERSat3co8Wu9Uoys6PEPbPoUp19lGTvrltRZKGJ9p6o"
WRONG_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEiLCJleHAiOjQxMDI0NDQ4MDAsInR5cGUiOiJhY2Nlc3MiLCJqdGkiOiIyMjIyMjIyMi0yMjIyLTIyMjItMjIyMi0yMjIyMjIyMjIyMjIifQ.aABKgYhs0GbPsaWdQhiIdOgEL8ITVEbGC8-RDwGeJXw"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _forge(header: dict, claims: dict, sig: bytes = b"") -> str:
    body = _b64(json.dumps(header).encode()) + "." + _b64(json.dumps(claims).encode())
    return body + "." + _b64(sig)


def _decode(token: str) -> dict:
    return jwt_compat.decode(token, SECRET, algorithms=["HS256"])


def test_tokens_minted_by_python_jose_decode() -> None:
    assert _decode(ACCESS) == ACCESS_CLAIMS
    assert _decode(DNS_AGENT) == DNS_AGENT_CLAIMS
    # python-jose never refused a future iat; neither may we.
    assert _decode(FUTURE_IAT)["iat"] == FAR - 1


def test_encoding_is_byte_identical_to_python_jose() -> None:
    assert jwt_compat.encode(ACCESS_CLAIMS, SECRET, algorithm="HS256") == ACCESS
    assert jwt_compat.encode(DNS_AGENT_CLAIMS, SECRET, algorithm="HS256") == DNS_AGENT


def test_a_short_secret_still_signs_and_verifies() -> None:
    token = jwt_compat.encode({"sub": "a", "exp": FAR}, "short")
    assert jwt_compat.decode(token, "short")["sub"] == "a"


@pytest.mark.parametrize(
    "token",
    [EXPIRED, FUTURE_NBF, WITH_AUD, INT_SUB, WRONG_KEY, "", "garbage", "a.b.c", ACCESS[:-3]],
)
def test_what_python_jose_refused_is_refused(token: str) -> None:
    with pytest.raises(JWTError):
        _decode(token)


def test_alg_none_and_foreign_algorithms_are_refused() -> None:
    claims = {"sub": "x", "exp": FAR}
    with pytest.raises(JWTError):
        _decode(_forge({"alg": "none", "typ": "JWT"}, claims))
    with pytest.raises(JWTError):
        _decode(_forge({"alg": "RS256", "typ": "JWT"}, claims, b"x" * 256))
    # HS512 correctly signed with the right secret is still not HS256.
    head = {"alg": "HS512", "typ": "JWT"}
    body = _b64(json.dumps(head).encode()) + "." + _b64(json.dumps(claims).encode())
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha512).digest()
    with pytest.raises(JWTError):
        _decode(body + "." + _b64(sig))


def test_non_object_claims_are_refused() -> None:
    body = _b64(b'{"alg":"HS256","typ":"JWT"}') + "." + _b64(b"[1,2]")
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest()
    with pytest.raises(JWTError):
        _decode(body + "." + _b64(sig))


def test_access_token_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.core.security.settings.secret_key", SECRET)
    uid, jti = str(uuid.uuid4()), str(uuid.uuid4())
    payload = decode_access_token(create_access_token(uid, jti=jti))
    assert payload["sub"] == uid and payload["jti"] == jti and payload["type"] == "access"
    assert isinstance(payload["exp"], int)
    # An old-format access token decodes through the real entry point too.
    assert decode_access_token(ACCESS)["jti"] == ACCESS_CLAIMS["jti"]
    with pytest.raises(JWTError):
        decode_access_token(EXPIRED)


def test_agent_token_round_trips_and_types_stay_separate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.config.settings.secret_key", SECRET)
    tok, _ = dns_tok.mint_agent_token("srv", "agent", "fp")
    assert dns_tok.verify_agent_token(tok)["sub"] == "srv"
    assert dns_tok.verify_agent_token(DNS_AGENT)["agent_id"] == "a1"
    for other in (dhcp_tok.verify_agent_token, lg_tok.verify_agent_token):
        with pytest.raises(JWTError):
            other(tok)
