"""A token that cannot be an HTTP header value is a 422, never a 500 (#1913).

httpx encodes header values as ASCII and raises while *building* a client
from one that is not. ``_detect_cidrs`` promises it never raises, and every
integration probe builds its Authorization header from operator input, so the
boundary refuses the credential with a message instead.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.kubernetes.router import _detect_cidrs
from app.core.header_credentials import header_credential_problem
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.feature_module import FeatureModule

BAD_TOKENS = [
    "tok’en",  # word-processor quote
    "café-token",
    "tok en",
    "token\n",
    "tok\r\nX-Evil: 1",
    "​token",  # zero-width space
]


async def _headers(db: AsyncSession, module: str) -> dict[str, str]:
    user = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Admin",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=True,
    )
    db.add(user)
    db.add(FeatureModule(id=module, enabled=True))
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
@pytest.mark.parametrize("token", BAD_TOKENS)
@pytest.mark.parametrize("path", ["detect-cidrs", "test"])
async def test_kubernetes_probe_422_on_unusable_token(
    client: AsyncClient, db_session: AsyncSession, path: str, token: str
) -> None:
    h = await _headers(db_session, "integrations.kubernetes")
    r = await client.post(
        f"/api/v1/kubernetes/clusters/{path}",
        json={"api_server_url": "https://127.0.0.1:6443", "token": token},
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "whitespace" in r.text or "HTTP header" in r.text


@pytest.mark.asyncio
async def test_kubernetes_probe_422_on_unparseable_url(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, "integrations.kubernetes")
    r = await client.post(
        "/api/v1/kubernetes/clusters/detect-cidrs",
        json={"api_server_url": "not a url", "token": "abc"},
        headers=h,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("module", "path", "body"),
    [
        ("integrations.tailscale", "tailscale/tenants/test", {"tailnet": "x", "api_key": "k’"}),
        (
            "integrations.netbird",
            "netbird/instances/test",
            {"api_url": "https://nb.test", "api_key": "k y"},
        ),
        ("integrations.meraki", "meraki/orgs/test", {"org_id": "1", "api_key": "ké"}),
        (
            "integrations.fortinet",
            "fortinet/firewalls/test",
            {"base_url": "https://fg.test", "api_token": "t\n’"},
        ),
        ("integrations.unifi", "unifi/controllers/test", {"api_key": "k’"}),
        ("integrations.paloalto", "paloalto/firewalls/test", {"api_key": "k’"}),
        (
            "integrations.proxmox",
            "proxmox/nodes/test",
            {"token_id": "root@pam!t", "token_secret": "s’"},
        ),
    ],
)
async def test_other_integrations_422_on_unusable_credential(
    client: AsyncClient, db_session: AsyncSession, module: str, path: str, body: dict
) -> None:
    h = await _headers(db_session, module)
    r = await client.post(f"/api/v1/{path}", json=body, headers=h)
    assert r.status_code == 422, r.text
    assert "whitespace" in r.text or "HTTP header" in r.text


@pytest.mark.asyncio
async def test_detect_cidrs_never_raises_on_a_bad_token() -> None:
    """The helper's own contract, independent of the endpoint's 422."""
    out = await _detect_cidrs(
        api_server_url="https://127.0.0.1:1", token="tok’en", ca_bundle_pem=""
    )
    assert out.pod_cidr is None and out.service_cidr is None
    assert out.messages


def test_problem_helper_accepts_real_tokens() -> None:
    assert header_credential_problem("eyJhbGciOi.JIUzI1NiIs-_=", "token") is None
    assert header_credential_problem("", "token") is None
    assert header_credential_problem(None, "token") is None
