"""#3631 — what the supervisor signs, and what it does with a sealed join token.

The control plane checks a signature over the method, the path AND query as
sent, a hash of the exact body bytes, a nonce, the timestamp and the
appliance id. These tests verify the signature each call site actually sends
against the bytes that actually went on the wire, so a call site that signs
one body and sends another (``json=`` re-serialised by httpx) or signs the
bare path and sends a query fails here rather than as a 403 in the field.
"""

from __future__ import annotations

import base64
import hashlib
import json
import types
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from spatium_supervisor import appliance_state as st
from spatium_supervisor import cert_auth, pcap_proxy, sealed_token
from spatium_supervisor import heartbeat as hb
from spatium_supervisor.identity import load_or_generate

APPLIANCE_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")


def _verify(request: httpx.Request, public_key: Ed25519PublicKey, target: str) -> None:
    """Check ``request``'s signature the way the control plane does, from
    the request as sent. Raises ``InvalidSignature`` when it does not hold."""
    h = request.headers
    assert h["X-Appliance-Signature-Version"] == "2"
    body = request.content
    assert h["X-Appliance-Content-SHA256"] == hashlib.sha256(body).hexdigest()
    payload = cert_auth.canonical_payload_v2(
        request.method,
        target,
        h["X-Appliance-Timestamp"],
        h["X-Appliance-Nonce"],
        str(APPLIANCE_ID),
        hashlib.sha256(body).hexdigest(),
    )
    public_key.verify(base64.b64decode(h["X-Appliance-Signature"]), payload)


def _sent_target(request: httpx.Request) -> str:
    return request.url.raw_path.decode("ascii")


# --- build_auth_headers -------------------------------------------------------


def test_signature_covers_body_and_query(tmp_path: Path) -> None:
    identity, _ = load_or_generate(tmp_path)
    pub = identity.private_key.public_key()
    body = b'{"a":1}'
    h = cert_auth.build_auth_headers(
        "POST", "/p?x=1", "CERT", identity.private_key, APPLIANCE_ID, body
    )
    sig = base64.b64decode(h["X-Appliance-Signature"])
    args = (h["X-Appliance-Timestamp"], h["X-Appliance-Nonce"], str(APPLIANCE_ID))

    def payload(target: str, content: bytes) -> bytes:
        return cert_auth.canonical_payload_v2(
            "POST",
            target,
            args[0],
            args[1],
            args[2],
            hashlib.sha256(content).hexdigest(),
        )

    pub.verify(sig, payload("/p?x=1", body))
    with pytest.raises(InvalidSignature):
        pub.verify(sig, payload("/p?x=2", body))
    with pytest.raises(InvalidSignature):
        pub.verify(sig, payload("/p", body))
    with pytest.raises(InvalidSignature):
        pub.verify(sig, payload("/p?x=1", b'{"a":2}'))


def test_every_request_gets_its_own_nonce(tmp_path: Path) -> None:
    identity, _ = load_or_generate(tmp_path)
    a = cert_auth.build_auth_headers(
        "POST", "/p", "CERT", identity.private_key, APPLIANCE_ID
    )
    b = cert_auth.build_auth_headers(
        "POST", "/p", "CERT", identity.private_key, APPLIANCE_ID
    )
    assert a["X-Appliance-Nonce"] != b["X-Appliance-Nonce"]
    assert a["X-Appliance-Signature"] != b["X-Appliance-Signature"]


# --- the heartbeat signs the bytes it sends -----------------------------------


def _quiet_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "collect", lambda: {"hostname_reported": "né", "x": [1, 2]})
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(st, "read_firewall_state", dict)
    monkeypatch.setattr(hb, "probe_port_conflicts", dict)
    monkeypatch.setattr(hb, "_capabilities_payload", dict)
    monkeypatch.setattr(
        hb, "_effective_control_plane_url", lambda cfg: "http://cp.invalid"
    )
    monkeypatch.setattr(hb, "load_cert", lambda d: "CERT")


def test_heartbeat_signature_holds_for_the_request_as_sent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _quiet_heartbeat(monkeypatch)
    identity, _ = load_or_generate(tmp_path)
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(503, json={"detail": "x"})

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=30, state_dir=tmp_path)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        hb.heartbeat_once(
            cfg, APPLIANCE_ID, "tok", identity, client, structlog.get_logger()  # type: ignore[arg-type]
        )
    assert len(sent) == 1
    request = sent[0]
    _verify(request, identity.private_key.public_key(), _sent_target(request))
    sent_body = json.loads(request.content)
    # The join-token key rides in the signed body.
    assert sent_body["join_token_public_key"] == sealed_token.public_key_b64()


# --- pcap: the query and the streamed body are signed -------------------------


def _pcap_cfg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    monkeypatch.setattr(
        pcap_proxy, "_effective_control_plane_url", lambda cfg: "http://cp.invalid"
    )
    monkeypatch.setattr(pcap_proxy, "load_cert", lambda d: "CERT")
    return types.SimpleNamespace(state_dir=tmp_path)


def test_pcap_upload_signs_the_query_and_the_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _pcap_cfg(monkeypatch, tmp_path)
    identity, _ = load_or_generate(tmp_path)
    pcap = tmp_path / "c.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"x" * 5000)
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        sent.append(request)
        return httpx.Response(200, json={"status": "done"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        pcap_proxy._upload_pcap(
            cfg, identity, client, str(APPLIANCE_ID), "cid-1", pcap, 7
        )
    (request,) = sent
    target = _sent_target(request)
    assert target.endswith("/pcap/upload/cid-1?packets=7")
    assert request.content == pcap.read_bytes()
    _verify(request, identity.private_key.public_key(), target)


def test_pcap_error_finalize_signs_the_error_query(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _pcap_cfg(monkeypatch, tmp_path)
    identity, _ = load_or_generate(tmp_path)
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"status": "failed"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        pcap_proxy._finalize_error(
            cfg,
            identity,
            client,
            str(APPLIANCE_ID),
            "cid-1",
            "tcpdump: no such device/eth9 & 100%",
        )
    (request,) = sent
    target = _sent_target(request)
    assert "?error=" in target
    _verify(request, identity.private_key.public_key(), target)


def test_pcap_progress_signs_its_json_body(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = _pcap_cfg(monkeypatch, tmp_path)
    identity, _ = load_or_generate(tmp_path)
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"cancel": False})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        pcap_proxy._post_progress(
            cfg,
            identity,
            client,
            str(APPLIANCE_ID),
            "cid-1",
            packets=3,
            bytes_captured=10,
            elapsed_s=1.5,
        )
    (request,) = sent
    assert json.loads(request.content)["packets"] == 3
    _verify(request, identity.private_key.public_key(), _sent_target(request))


# --- sealed join token ---------------------------------------------------------

# Produced by the control plane's ``app.services.appliance.sealed_token.seal``
# for the X25519 key with private bytes 1..32, appliance APPLIANCE_ID and the
# plaintext below. Pins that the two implementations agree byte for byte.
_VECTOR_PLAINTEXT = "K10abc::server:secret"
_VECTOR_SEALED = (
    "t3wNY+8en9i7fQOfuYJap9QJxu6IZd0zBkOMQoBfK0hLuUCZTuAndtfg2uEExBjPxqUz"
    "bWqBCXJPY4fYBl5U/rORCGdJMTyKJs2nnD3etIY3"
)


@pytest.fixture
def fixed_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sealed_token,
        "_private_key",
        X25519PrivateKey.from_private_bytes(bytes(range(1, 33))),
    )


def test_sealed_token_from_the_control_plane_opens(fixed_key: None) -> None:
    assert (
        sealed_token.public_key_b64() == "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="
    )
    assert sealed_token.open_sealed(_VECTOR_SEALED, APPLIANCE_ID) == _VECTOR_PLAINTEXT


def test_sealed_token_does_not_open_for_another_appliance_or_key(
    monkeypatch: pytest.MonkeyPatch, fixed_key: None
) -> None:
    assert sealed_token.open_sealed(_VECTOR_SEALED, uuid.uuid4()) is None
    monkeypatch.setattr(sealed_token, "_private_key", X25519PrivateKey.generate())
    assert sealed_token.open_sealed(_VECTOR_SEALED, APPLIANCE_ID) is None
    assert sealed_token.open_sealed("not base64!", APPLIANCE_ID) is None


def test_heartbeat_reads_the_sealed_join_token(fixed_key: None) -> None:
    log = structlog.get_logger()
    out = {
        "desired_k3s_join_token_sealed": _VECTOR_SEALED,
        "desired_k3s_join_token": None,
    }
    assert hb._join_token(out, APPLIANCE_ID, log) == _VECTOR_PLAINTEXT  # type: ignore[arg-type]
    # A sealed token that does not open is not a token, whatever else came.
    bad = {
        "desired_k3s_join_token_sealed": "AAAA" * 20,
        "desired_k3s_join_token": "plain",
    }
    assert hb._join_token(bad, APPLIANCE_ID, log) is None  # type: ignore[arg-type]
