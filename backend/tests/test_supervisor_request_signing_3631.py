"""#3631 — a supervisor's request signature binds the whole request, once.

Supervisor requests are authenticated by an Ed25519 signature in headers.
The signature now covers the full target (path plus raw query) and a hash of
the exact body bytes, each signature is accepted once, and the k3s join token
in a heartbeat response is sealed to a key the supervisor sent in its signed
body instead of returned in clear. Older supervisors (no version header) keep
working only while ``appliance_legacy_signature_allowed`` is set.

These tests drive the real gate end to end: a real CA, a real supervisor
cert, and a real Ed25519 key, with Redis replaced by an in-memory SET NX.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.crypto import encrypt_str
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    DESIRED_CLUSTER_ROLE_MEMBER,
    Appliance,
)
from app.models.pcap import PacketCapture
from app.models.settings import PlatformSettings
from app.services.appliance import cert_auth, sealed_token
from app.services.appliance.ca import ensure_ca, generate_session_token, sign_supervisor_cert

HEARTBEAT = "/api/v1/appliance/supervisor/heartbeat"
JOIN_TOKEN = "K10deadbeef::server:abc123"


class _FakeRedis:
    def __init__(self, store: dict[str, Any]) -> None:
        self.store = store

    async def set(self, key: str, value: Any, ex: int | None = None, nx: bool = False) -> bool:
        if nx and key in self.store:
            return False
        self.store[key] = (value, ex)
        return True

    async def get(self, key: str) -> Any:
        entry = self.store.get(key)
        return None if entry is None else entry[0]

    async def aclose(self) -> None:
        return None


@pytest.fixture
def redis_store(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    store: dict[str, Any] = {}
    monkeypatch.setattr(
        cert_auth, "make_async_redis", lambda *_a, **_k: _FakeRedis(store), raising=False
    )
    return store


class _Supervisor:
    def __init__(self, row: Appliance, key: Ed25519PrivateKey, cert_pem: str, token: str):
        self.row = row
        self.key = key
        self.cert_pem = cert_pem
        self.session_token = token

    def _base(self) -> dict[str, str]:
        return {
            "X-Appliance-Cert": base64.b64encode(self.cert_pem.encode()).decode(),
            "X-Appliance-Timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        }

    def headers(self, target: str, body: bytes = b"", *, method: str = "POST") -> dict[str, str]:
        """The current form, built independently of the server's code."""
        h = self._base()
        nonce = secrets.token_hex(16)
        digest = hashlib.sha256(body).hexdigest()
        payload = "\n".join(
            (
                "spatium-appliance-v2",
                method,
                target,
                h["X-Appliance-Timestamp"],
                nonce,
                str(self.row.id),
                digest,
            )
        ).encode()
        h.update(
            {
                "X-Appliance-Signature-Version": "2",
                "X-Appliance-Nonce": nonce,
                "X-Appliance-Content-SHA256": digest,
                "X-Appliance-Signature": base64.b64encode(self.key.sign(payload)).decode(),
                "Content-Type": "application/json",
            }
        )
        return h

    def legacy_headers(self, path: str, *, method: str = "POST") -> dict[str, str]:
        """What a supervisor older than #3631 sends."""
        h = self._base()
        payload = f"{method} {path}\n{h['X-Appliance-Timestamp']}\n{self.row.id}".encode()
        h["X-Appliance-Signature"] = base64.b64encode(self.key.sign(payload)).decode()
        return h


async def _supervisor(db: AsyncSession, *, member_join: bool = False) -> _Supervisor:
    s = await db.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db.add(s)
    s.supervisor_registration_enabled = True
    key = Ed25519PrivateKey.generate()
    der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    fp = hashlib.sha256(der).hexdigest()
    token, token_hash = generate_session_token()
    row = Appliance(
        id=uuid.uuid4(),
        hostname=f"sup-{uuid.uuid4().hex[:8]}",
        public_key_der=der,
        public_key_fingerprint=fp,
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="appliance",
        session_token_hash=token_hash,
    )
    if member_join:
        row.desired_cluster_role = DESIRED_CLUSTER_ROLE_MEMBER
        row.desired_k3s_join_token_encrypted = encrypt_str(JOIN_TOKEN)
    ca = await ensure_ca(db)
    cert_pem, _serial, _issued, _expires = sign_supervisor_cert(
        ca=ca,
        appliance_id=row.id,
        public_key_der=der,
        public_key_fingerprint=fp,
        hostname=row.hostname,
    )
    row.cert_pem = cert_pem
    db.add(row)
    await db.commit()
    return _Supervisor(row, key, cert_pem, token)


def _hb_body(sup: _Supervisor, **extra: Any) -> bytes:
    return json.dumps({"appliance_id": str(sup.row.id), **extra}).encode()


# --- body and target binding ---------------------------------------------------


async def test_signed_heartbeat_is_accepted(
    client: AsyncClient, db_session: AsyncSession, redis_store: dict[str, Any]
) -> None:
    sup = await _supervisor(db_session)
    body = _hb_body(sup)
    r = await client.post(HEARTBEAT, content=body, headers=sup.headers(HEARTBEAT, body))
    assert r.status_code == 200, r.text
    assert len(redis_store) == 1


async def test_heartbeat_with_a_changed_body_is_refused(
    client: AsyncClient, db_session: AsyncSession, redis_store: dict[str, Any]
) -> None:
    sup = await _supervisor(db_session)
    signed = _hb_body(sup)
    sent = _hb_body(sup, installed_appliance_version="2099.01.01-1")
    r = await client.post(HEARTBEAT, content=sent, headers=sup.headers(HEARTBEAT, signed))
    # No session token in the body, so the cert is the only credential.
    assert r.status_code == 403, r.text
    await db_session.refresh(sup.row)
    assert sup.row.installed_appliance_version != "2099.01.01-1"

    # The same body, signed as sent, is accepted.
    r = await client.post(HEARTBEAT, content=sent, headers=sup.headers(HEARTBEAT, sent))
    assert r.status_code == 200, r.text
    await db_session.refresh(sup.row)
    assert sup.row.installed_appliance_version == "2099.01.01-1"


async def test_changed_query_is_refused(
    client: AsyncClient, db_session: AsyncSession, redis_store: dict[str, Any]
) -> None:
    sup = await _supervisor(db_session)
    cap = PacketCapture(
        vantage_kind="appliance",
        appliance_id=sup.row.id,
        vantage_label="appl",
        interface="eth0",
        bpf_filter="port 53",
        snaplen=256,
        max_duration_s=30,
        status="running",
    )
    db_session.add(cap)
    await db_session.commit()
    path = f"/api/v1/appliance/supervisor/pcap/upload/{cap.id}"

    r = await client.post(f"{path}?error=forged", headers=sup.headers(f"{path}?error=real"))
    assert r.status_code == 403, r.text
    await db_session.refresh(cap)
    assert cap.status == "running"

    # An unsigned query added to a path-only signature is refused too.
    r = await client.post(f"{path}?error=forged", headers=sup.headers(path))
    assert r.status_code == 403, r.text

    r = await client.post(f"{path}?error=real", headers=sup.headers(f"{path}?error=real"))
    assert r.status_code == 200, r.text
    await db_session.refresh(cap)
    assert cap.status == "failed"


async def test_pcap_upload_keeps_only_the_signed_bytes(
    client: AsyncClient,
    db_session: AsyncSession,
    redis_store: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    monkeypatch.setenv("SPATIUM_PCAP_DIR", str(tmp_path))
    sup = await _supervisor(db_session)
    cap = PacketCapture(
        vantage_kind="appliance",
        appliance_id=sup.row.id,
        vantage_label="appl",
        interface="eth0",
        bpf_filter="port 53",
        snaplen=256,
        max_duration_s=30,
        status="running",
    )
    db_session.add(cap)
    await db_session.commit()
    target = f"/api/v1/appliance/supervisor/pcap/upload/{cap.id}?packets=2"
    genuine = b"\xd4\xc3\xb2\xa1genuine"
    forged = b"\xd4\xc3\xb2\xa1forged!"

    headers = sup.headers(target, genuine)
    headers["Content-Type"] = "application/octet-stream"
    r = await client.post(target, content=forged, headers=headers)
    assert r.status_code == 403, r.text
    assert list(tmp_path.iterdir()) == []
    await db_session.refresh(cap)
    assert cap.status == "running"
    assert cap.pcap_sha256 is None

    headers = sup.headers(target, genuine)
    headers["Content-Type"] = "application/octet-stream"
    r = await client.post(target, content=genuine, headers=headers)
    assert r.status_code == 200, r.text
    await db_session.refresh(cap)
    assert cap.pcap_sha256 == hashlib.sha256(genuine).hexdigest()


# --- single use -------------------------------------------------------------


async def test_the_same_signed_request_is_accepted_once(
    client: AsyncClient, db_session: AsyncSession, redis_store: dict[str, Any]
) -> None:
    sup = await _supervisor(db_session)
    body = _hb_body(sup, session_token=sup.session_token)
    headers = sup.headers(HEARTBEAT, body)
    r = await client.post(HEARTBEAT, content=body, headers=headers)
    assert r.status_code == 200, r.text
    # The same headers again: refused, and not rescued by the session token
    # in the body.
    r = await client.post(HEARTBEAT, content=body, headers=headers)
    assert r.status_code == 401, r.text


async def test_replay_is_refused_on_the_proxy_channels(
    client: AsyncClient, db_session: AsyncSession, redis_store: dict[str, Any]
) -> None:
    sup = await _supervisor(db_session)
    path = "/api/v1/appliance/supervisor/nettool/reply/r1"
    body = json.dumps({"request_id": "r1", "result": {"ok": True}}).encode()
    headers = sup.headers(path, body)
    r = await client.post(path, content=body, headers=headers)
    assert r.status_code == 200, r.text
    r = await client.post(path, content=body, headers=headers)
    assert r.status_code == 401, r.text


async def test_replay_guard_fails_open_when_redis_is_unreachable(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _down(*_a: Any, **_k: Any) -> Any:
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr(cert_auth, "make_async_redis", _down, raising=False)
    sup = await _supervisor(db_session)
    body = _hb_body(sup)
    r = await client.post(HEARTBEAT, content=body, headers=sup.headers(HEARTBEAT, body))
    assert r.status_code == 200, r.text


# --- compatibility window --------------------------------------------------------


async def test_legacy_form_is_accepted_only_while_allowed(
    client: AsyncClient,
    db_session: AsyncSession,
    redis_store: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sup = await _supervisor(db_session)
    body = _hb_body(sup)
    monkeypatch.setattr(settings, "appliance_legacy_signature_allowed", True)
    r = await client.post(
        HEARTBEAT,
        content=body,
        headers={**sup.legacy_headers(HEARTBEAT), "Content-Type": "application/json"},
    )
    assert r.status_code == 200, r.text
    assert cert_auth.legacy_signature_use().get(str(sup.row.id), 0) >= 1

    monkeypatch.setattr(settings, "appliance_legacy_signature_allowed", False)
    r = await client.post(
        HEARTBEAT,
        content=body,
        headers={**sup.legacy_headers(HEARTBEAT), "Content-Type": "application/json"},
    )
    assert r.status_code == 403, r.text


async def test_heartbeat_answer_advertises_the_signature_form(
    client: AsyncClient, db_session: AsyncSession, redis_store: dict[str, Any]
) -> None:
    """A supervisor learns from this header that the control plane checks the
    current form; with no header it signs the legacy form, which is what an
    older control plane checks."""
    sup = await _supervisor(db_session)
    body = _hb_body(sup)
    r = await client.post(HEARTBEAT, content=body, headers=sup.headers(HEARTBEAT, body))
    assert r.status_code == 200, r.text
    assert r.headers.get("X-Appliance-Signature-Versions") == "2"
    # Also on a heartbeat accepted on the session token (the cert not
    # validating), so a current supervisor is never moved to the older form.
    body = _hb_body(sup, session_token=sup.session_token)
    r = await client.post(HEARTBEAT, content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.headers.get("X-Appliance-Signature-Versions") == "2"


async def test_identical_legacy_requests_in_one_second_are_both_accepted(
    client: AsyncClient,
    db_session: AsyncSession,
    redis_store: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An older supervisor's poll, reply and next poll often land in the same
    second, and with no nonce the two polls sign identically. The second must
    not be refused as a repeat, or every follow-up request of a burst waits out
    the proxy backoff. A repeat with a different body still is."""
    monkeypatch.setattr(settings, "appliance_legacy_signature_allowed", True)
    sup = await _supervisor(db_session)
    body = _hb_body(sup)
    headers = {**sup.legacy_headers(HEARTBEAT), "Content-Type": "application/json"}
    r = await client.post(HEARTBEAT, content=body, headers=headers)
    assert r.status_code == 200, r.text
    r = await client.post(HEARTBEAT, content=body, headers=headers)
    assert r.status_code == 200, r.text

    forged = _hb_body(sup, installed_appliance_version="2099.01.01-1")
    r = await client.post(HEARTBEAT, content=forged, headers=headers)
    assert r.status_code == 401, r.text
    await db_session.refresh(sup.row)
    assert sup.row.installed_appliance_version != "2099.01.01-1"

    # Past the allowance, even the identical request is a repeat.
    monkeypatch.setattr(cert_auth, "_LEGACY_REPEAT_WINDOW_S", -1.0)
    r = await client.post(HEARTBEAT, content=body, headers=headers)
    assert r.status_code == 401, r.text


async def test_a_versioned_request_is_never_checked_as_legacy(
    client: AsyncClient,
    db_session: AsyncSession,
    redis_store: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "appliance_legacy_signature_allowed", True)
    sup = await _supervisor(db_session)
    body = _hb_body(sup)
    headers = {
        **sup.legacy_headers(HEARTBEAT),
        "X-Appliance-Signature-Version": "2",
        "X-Appliance-Nonce": secrets.token_hex(16),
        "X-Appliance-Content-SHA256": hashlib.sha256(body).hexdigest(),
        "Content-Type": "application/json",
    }
    r = await client.post(HEARTBEAT, content=body, headers=headers)
    assert r.status_code == 403, r.text


# --- join token ---------------------------------------------------------------


def _open(sealed_b64: str, key: X25519PrivateKey, appliance_id: uuid.UUID) -> str:
    """The supervisor's opening, written out here so the test does not lean on
    the server's own code."""
    raw = base64.b64decode(sealed_b64)
    eph, nonce, ct = raw[:32], raw[32:44], raw[44:]
    recipient = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = key.exchange(X25519PublicKey.from_public_bytes(eph))
    k = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"spatiumddi sealed token v1" + eph + recipient,
    ).derive(shared)
    return ChaCha20Poly1305(k).decrypt(nonce, ct, str(appliance_id).encode()).decode()


def _pub_b64(key: X25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


async def test_join_token_is_returned_only_sealed_to_the_signed_key(
    client: AsyncClient, db_session: AsyncSession, redis_store: dict[str, Any]
) -> None:
    sup = await _supervisor(db_session, member_join=True)
    key = X25519PrivateKey.generate()
    body = _hb_body(sup, join_token_public_key=_pub_b64(key))
    r = await client.post(HEARTBEAT, content=body, headers=sup.headers(HEARTBEAT, body))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["desired_k3s_join_token"] is None
    assert JOIN_TOKEN not in r.text
    assert _open(out["desired_k3s_join_token_sealed"], key, sup.row.id) == JOIN_TOKEN


async def test_join_token_is_withheld_without_a_key_in_a_signed_body(
    client: AsyncClient,
    db_session: AsyncSession,
    redis_store: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "appliance_legacy_signature_allowed", True)
    sup = await _supervisor(db_session, member_join=True)

    # A current supervisor that sent no key.
    body = _hb_body(sup)
    r = await client.post(HEARTBEAT, content=body, headers=sup.headers(HEARTBEAT, body))
    assert r.status_code == 200, r.text
    assert r.json()["desired_k3s_join_token"] is None
    assert r.json()["desired_k3s_join_token_sealed"] is None

    # A legacy signature does not cover the body, so a key in it could be
    # anyone's: nothing is sealed to it, and nothing goes out in clear.
    key = X25519PrivateKey.generate()
    body = _hb_body(sup, join_token_public_key=_pub_b64(key))
    r = await client.post(
        HEARTBEAT,
        content=body,
        headers={**sup.legacy_headers(HEARTBEAT), "Content-Type": "application/json"},
    )
    assert r.status_code == 200, r.text
    assert JOIN_TOKEN not in r.text
    assert r.json()["desired_k3s_join_token_sealed"] is None


def test_seal_refuses_a_key_that_is_not_x25519() -> None:
    with pytest.raises(sealed_token.SealError):
        sealed_token.seal("x", base64.b64encode(b"short").decode(), uuid.uuid4())
    with pytest.raises(sealed_token.SealError):
        # The identity point: a low-order key whose shared secret is all zeros.
        sealed_token.seal("x", base64.b64encode(bytes(32)).decode(), uuid.uuid4())


async def test_promote_refuses_a_supervisor_too_old_for_a_sealed_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An older supervisor is never handed the join token (it sends no key),
    so promoting it would leave the join waiting with nothing to say why.
    The promote is refused, naming the fix."""
    import os  # noqa: PLC0415

    from app.core.security import create_access_token, hash_password  # noqa: PLC0415
    from app.models.appliance import CLUSTER_ROLE_PRIMARY  # noqa: PLC0415
    from app.models.auth import User  # noqa: PLC0415

    user = User(
        username="cp3631",
        email="cp3631@example.com",
        display_name="cp3631",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.flush()
    auth = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    def _row(hostname: str, **kw: Any) -> Appliance:
        der = os.urandom(32)
        row = Appliance(
            id=uuid.uuid4(),
            hostname=hostname,
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            **kw,
        )
        db_session.add(row)
        return row

    _row(
        "seed",
        appliance_variant="control-plane",
        cluster_role=CLUSTER_ROLE_PRIMARY,
        node_ip="10.0.0.1",
        k3s_join_token_encrypted=encrypt_str("K10::servertoken"),
    )
    old = _row(
        "old1",
        appliance_variant="appliance",
        capabilities={"supervisor_version": "1.0.0-beta.4"},
    )
    new = _row(
        "new1",
        appliance_variant="appliance",
        capabilities={"supervisor_version": "1.0.0-beta.5", "sealed_join_token": True},
    )
    await db_session.commit()

    promote = "/api/v1/appliance/fleet/control-plane/promote"
    r = await client.post(promote, json={"appliance_ids": [str(old.id), str(new.id)]}, headers=auth)
    assert r.status_code == 422, r.text
    assert "too old" in r.text and "old1" in r.text
    await db_session.refresh(old)
    assert old.desired_cluster_role is None
