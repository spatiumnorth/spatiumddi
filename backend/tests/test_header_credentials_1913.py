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
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.fortinet.router import TestConnectionRequest as FgTest
from app.api.v1.kubernetes.router import ClusterUpdate as KUpdate
from app.api.v1.kubernetes.router import TestConnectionRequest as KTest
from app.api.v1.kubernetes.router import _detect_cidrs
from app.api.v1.meraki.router import TestConnectionRequest as MkTest
from app.api.v1.netbird.router import TestConnectionRequest as NbTest
from app.api.v1.panos.router import TestConnectionRequest as PaTest
from app.api.v1.proxmox.router import NodeUpdate as PxUpdate
from app.api.v1.proxmox.router import TestConnectionRequest as PxTest
from app.api.v1.tailscale.router import TestConnectionRequest as TsTest
from app.api.v1.unifi.router import TestConnectionRequest as UfTest
from app.core.header_credentials import header_credential_problem, header_secret
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.feature_module import FeatureModule
from app.services.backup.targets.base import DestinationConfigError
from app.services.backup.targets.https_put import HttpsPutDestination

BAD_TOKENS = [
    "tok’en",  # word-processor quote
    "café-token",
    "tok en",
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


# Real token shapes, one per provider whose header the validator guards. None
# of these may be refused (a valid token turned away is worse than the 500).
REAL_TOKENS = [
    (
        "kubernetes",
        KTest,
        "token",
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1rT0J4In0.eyJpc3MiOiJrdWJlcm5ldGVzIn0.c2ln-_",
    ),
    ("tailscale", TsTest, "api_key", "tskey-api-" + "kTESTfake01CNTRL" + "-" + "x" * 26),
    ("netbird", NbTest, "api_key", "nbp_0123456789abcdefABCDEF0123456789ab"),
    ("meraki", MkTest, "api_key", "6bec40cf957de430a6f1f2baa056b99a4fac9ea0"),
    ("fortigate", FgTest, "api_token", "Hs3kq8NnmQr0b5N4cG7tN6xNr1Hyf0"),
    ("unifi", UfTest, "api_key", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY"),
    ("panos", PaTest, "api_key", "LUFRPT1hbWJ3ZkFsS0Rkc3I4bjEzZk5TVz0=Rm9vYmFyYmF6cXV4+/QQ=="),
    ("proxmox secret", PxTest, "token_secret", "4f1b2c3d-5e6f-7081-92a3-b4c5d6e7f809"),
    ("proxmox id", PxTest, "token_id", "spatium-sync@pve!ddi_mirror-1.0"),
]


# ids= keeps the token out of the test node id: node ids are written to
# backend/.test_durations, and a token-shaped id there trips secret scanning.
@pytest.mark.parametrize(
    ("label", "model", "field", "token"), REAL_TOKENS, ids=[r[0] for r in REAL_TOKENS]
)
def test_real_tokens_pass_unchanged(label: str, model: type, field: str, token: str) -> None:
    assert getattr(model(**{field: token}), field) == token, label


# ids= keeps the token out of the test node id: node ids are written to
# backend/.test_durations, and a token-shaped id there trips secret scanning.
@pytest.mark.parametrize(
    ("label", "model", "field", "token"), REAL_TOKENS, ids=[r[0] for r in REAL_TOKENS]
)
def test_surrounding_whitespace_is_stripped_not_refused(
    label: str, model: type, field: str, token: str
) -> None:
    """A token pasted with its trailing newline (the commonest real case)."""
    for pasted in (token + "\n", "  " + token + "\r\n", "\t" + token + " "):
        assert getattr(model(**{field: pasted}), field) == token, label


@pytest.mark.parametrize("keep", [None, ""])
def test_keep_the_stored_secret_passes_untouched(keep: str | None) -> None:
    """On every update, None / "" mean "keep the stored credential"."""
    assert KUpdate(token=keep).token == keep
    assert PxUpdate(token_secret=keep).token_secret == keep


def test_a_whitespace_only_credential_is_refused() -> None:
    with pytest.raises(ValidationError, match="blank"):
        KTest(token=" \n ")


@pytest.mark.asyncio
async def test_detect_cidrs_sends_a_stripped_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A trailing newline is not a 422: the probe runs (and fails to reach
    the unreachable port) with the token stripped."""
    h = await _headers(db_session, "integrations.kubernetes")
    r = await client.post(
        "/api/v1/kubernetes/clusters/detect-cidrs",
        json={"api_server_url": "https://127.0.0.1:1", "token": "token\n"},
        headers=h,
    )
    assert r.status_code == 200, r.text


def test_no_response_model_validates_a_header_credential() -> None:
    """Validation is on input only. A response model carrying the validator
    turns a read of a row stored before it existed into a 500 (Proxmox's
    NodeResponse and PAN-OS's TestConnectionResponse briefly did)."""
    import re

    from pydantic import BaseModel

    import app.main  # noqa: F401 — import every router's schemas

    offenders: list[str] = []
    stack: list[type] = list(BaseModel.__subclasses__())
    seen: set[type] = set()
    while stack:
        m = stack.pop()
        if m in seen:
            continue
        seen.add(m)
        stack.extend(m.__subclasses__())
        if not m.__module__.startswith("app.") or not re.search(
            r"(Response|Out|Read)$", m.__name__
        ):
            continue
        for dec in m.__pydantic_decorators__.field_validators.values():
            if dec.func is header_secret:
                offenders.append(f"{m.__module__}.{m.__name__}")
    assert not offenders, offenders


# ── backup https_put (#1913 sweep) ─────────────────────────────────────


@pytest.mark.parametrize(
    "config",
    [
        {"auth": "bearer", "credential": "tok\u2019en"},
        {"auth": "header", "header_name": "X-Api-Key", "credential": "caf\u00e9"},
        {"auth": "header", "header_name": "X Api Key", "credential": "abc"},
        {"auth": "none", "extra_headers": "X-Tenant: \u00e9quipe"},
    ],
)
def test_https_put_refuses_a_header_httpx_cannot_send(config: dict) -> None:
    """Uncaught, httpx's UnicodeEncodeError escaped the probe as a 500 and a
    scheduled run with the row left ``in_progress`` forever."""
    with pytest.raises(DestinationConfigError):
        HttpsPutDestination().validate_config({"url": "https://up.example/b/", **config})


def test_https_put_accepts_a_pasted_credential_and_strips_it_when_sent() -> None:
    d = HttpsPutDestination()
    cfg = {"url": "https://up.example/b/", "auth": "bearer", "credential": "abc123\n"}
    d.validate_config(cfg)
    assert d._headers(cfg, content_type="x")["Authorization"] == "Bearer abc123"


# ── webhooks (#1913 sweep) ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_header_httpx_cannot_send_is_a_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, "integrations.kubernetes")
    base = {"name": "w", "url": "https://hook.example/x"}
    r = await client.post(
        "/api/v1/webhooks", json={**base, "headers": {"X-Tenant": "\u00e9quipe"}}, headers=h
    )
    assert r.status_code == 422, r.text
    r = await client.post("/api/v1/webhooks", json={**base, "headers": {"X Bad": "v"}}, headers=h)
    assert r.status_code == 422, r.text
    r = await client.post(
        "/api/v1/webhooks", json={**base, "headers": {"Authorization": " Bearer a b\n"}}, headers=h
    )
    assert r.status_code in (200, 201), r.text


@pytest.mark.asyncio
async def test_webhook_delivery_with_a_stored_unsendable_header_fails_not_raises() -> None:
    """A row saved before the schema refused it is a failed delivery."""
    import httpx

    from app.core.crypto import encrypt_dict
    from app.models.event_subscription import EventOutbox, EventSubscription
    from app.services.event_delivery import _deliver_one

    sub = EventSubscription(
        id=uuid.uuid4(),
        name="w",
        url="https://127.0.0.1:1/x",
        headers_encrypted=encrypt_dict({"X-Tenant": "\u00e9quipe"}),
        timeout_seconds=1,
    )
    row = EventOutbox(id=uuid.uuid4(), subscription_id=sub.id, event_type="t", payload={})
    async with httpx.AsyncClient() as c:
        code, err = await _deliver_one(c, sub, row, "", "dev")
    assert code is None and err
    # Names the header the operator has to re-save, never the value.
    assert "'X-Tenant'" in err
    assert "quipe" not in err and "\u00e9" not in err
