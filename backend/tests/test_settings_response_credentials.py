"""``GET /settings`` reports whether a credential is configured, never its value.

Every credential-shaped value stored on ``platform_settings`` is seeded here
directly on the row, then the settings document is read back by a plain
signed-in user and by a superadmin. Neither response may carry the stored
plaintext or its ciphertext; the UI only gets the ``*_set`` flags (and, for a
webhook URL, its scheme and host).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.settings import PlatformSettings

# Fixtures only; nothing here is ever contacted.
_WEBHOOK_URL = "https://hooks.chat.example/services/T0/B0/urlPathFixture1"
_WEBHOOK_AUTH = "Bearer headerFixture2"
_FINGERBANK = "fingerbankFixture3"
_COMMUNITY = "communityFixture4"
_V3_AUTH = "v3AuthFixture5"
_V3_PRIV = "v3PrivFixture6"
_CA_PEM = "-----BEGIN CERTIFICATE-----\ncaPemFixture7\n-----END CERTIFICATE-----"
_GPG = "-----BEGIN PGP PUBLIC KEY BLOCK-----\ngpgFixture8\n-----END PGP PUBLIC KEY BLOCK-----"
_APT_PASS = "aptPassFixture9"
_PROXY_PASS = "proxyPassFixture10"

_PLAINTEXT = (
    "urlPathFixture1",
    "headerFixture2",
    _FINGERBANK,
    _COMMUNITY,
    _V3_AUTH,
    _V3_PRIV,
    "caPemFixture7",
    "gpgFixture8",
    _APT_PASS,
    _PROXY_PASS,
)


def _enc(value: str) -> bytes:
    return encrypt_str(value)


async def _seed(db: AsyncSession) -> list[str]:
    """Store one of every credential; return the ciphertexts written."""
    ciphertexts = {
        "url": _enc(_WEBHOOK_URL),
        "auth": _enc(_WEBHOOK_AUTH),
        "fingerbank": _enc(_FINGERBANK),
        "community": _enc(_COMMUNITY),
        "v3_auth": _enc(_V3_AUTH).decode("ascii"),
        "v3_priv": _enc(_V3_PRIV).decode("ascii"),
        "ca": _enc(_CA_PEM).decode("ascii"),
        "gpg": _enc(_GPG).decode("ascii"),
        "apt_pass": _enc(_APT_PASS).decode("ascii"),
    }
    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    ps.audit_forward_webhook_enabled = True
    ps.audit_forward_webhook_url_encrypted = ciphertexts["url"]
    ps.audit_forward_webhook_auth_header_encrypted = ciphertexts["auth"]
    ps.fingerbank_api_key_encrypted = ciphertexts["fingerbank"]
    ps.snmp_community_encrypted = ciphertexts["community"]
    ps.snmp_v3_users = [
        {
            "username": "monitor",
            "auth_protocol": "sha",
            "auth_pass_enc": ciphertexts["v3_auth"],
            "priv_protocol": "aes",
            "priv_pass_enc": ciphertexts["v3_priv"],
        }
    ]
    ps.syslog_targets = [
        {
            "host": "logs.example.test",
            "port": 6514,
            "protocol": "tls",
            "ca_cert_pem": ciphertexts["ca"],
        }
    ]
    ps.apt_gpg_keys = [{"key_id": "mirror", "comment": "", "armoured_text_enc": ciphertexts["gpg"]}]
    ps.apt_auth = [
        {"machine": "mirror.example.test", "login": "apt", "password_enc": ciphertexts["apt_pass"]}
    ]
    ps.apt_proxy_http = f"http://proxyuser:{_PROXY_PASS}@proxy.example.test:3128"
    ps.apt_proxy_https = f"http://proxyuser:{_PROXY_PASS}@proxy.example.test:3128"
    await db.flush()
    return [c.decode("ascii") if isinstance(c, bytes) else c for c in ciphertexts.values()]


async def _token(db: AsyncSession, *, superadmin: bool) -> dict[str, str]:
    user = User(
        username=f"settings-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Settings Reader",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.parametrize("superadmin", [False, True], ids=["signed_in_user", "superadmin"])
async def test_settings_response_carries_set_flags_not_credential_values(
    client: AsyncClient, db_session: AsyncSession, superadmin: bool
) -> None:
    ciphertexts = await _seed(db_session)
    headers = await _token(db_session, superadmin=superadmin)

    resp = await client.get("/api/v1/settings", headers=headers)
    assert resp.status_code == 200, resp.text

    for value in _PLAINTEXT:
        assert value not in resp.text, value
    for value in ciphertexts:
        assert value not in resp.text

    data = resp.json()
    for raw_field in (
        "audit_forward_webhook_url",
        "audit_forward_webhook_auth_header",
        "audit_forward_webhook_url_encrypted",
        "audit_forward_webhook_auth_header_encrypted",
        "fingerbank_api_key",
        "fingerbank_api_key_encrypted",
        "snmp_community",
        "snmp_community_encrypted",
    ):
        assert raw_field not in data
    assert data["audit_forward_webhook_url_set"] is True
    assert data["audit_forward_webhook_auth_header_set"] is True
    assert data["audit_forward_webhook_url_display"] == "https://hooks.chat.example/…"
    assert data["fingerbank_api_key_set"] is True
    assert data["snmp_community_set"] is True
    assert data["snmp_v3_users"][0]["auth_pass_set"] is True
    assert data["snmp_v3_users"][0]["priv_pass_set"] is True
    assert data["syslog_targets"][0]["ca_cert_set"] is True
    assert data["apt_gpg_keys"][0]["armoured_text_set"] is True
    assert data["apt_auth"][0]["password_set"] is True
    assert "proxy.example.test" in data["apt_proxy_http"]
