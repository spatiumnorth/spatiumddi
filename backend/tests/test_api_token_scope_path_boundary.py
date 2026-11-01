"""API-token scopes match their path prefix on a whole path segment.

``dns:write`` covers ``/api/v1/dns`` and everything beneath it, and nothing
else: ``/api/v1/dnsbl`` (IP reputation lists) and ``/api/v1/dns-threat``
(threat analytics) are separate surfaces that only share the spelling. The
same rule holds for every scope, so a router mounted later under a name that
starts with an existing prefix is not silently granted to existing tokens.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_token, hash_password
from app.models.auth import APIToken, User
from app.models.feature_module import FeatureModule
from app.services.api_token_scopes import scope_matches_request

# ── Unit: the matcher ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/dnsbl/lists",
        "/api/v1/dnsbl/pinned",
        "/api/v1/dnsbl/settings",
        "/api/v1/dns-threat/mutes",
        "/api/v1/dns-threat/mutes/10.0.0.1",
        "/api/v1/dns-pools",
        "/api/v1/dnsx",
    ],
)
def test_dns_write_does_not_cover_sibling_mounts(path: str) -> None:
    assert scope_matches_request(["dns:write"], "POST", path) is False
    assert scope_matches_request(["dns:write"], "DELETE", path) is False


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/dns",
        "/api/v1/dns/",
        "/api/v1/dns/groups",
        "/api/v1/dns/groups/abc/zones",
        "/api/v1/dns/blocklists",
        "/api/v1/dns/pools/abc",
    ],
)
def test_dns_write_covers_its_own_surface(path: str) -> None:
    assert scope_matches_request(["dns:write"], "POST", path) is True


def test_dns_write_still_excludes_the_agent_surface() -> None:
    assert scope_matches_request(["dns:write"], "POST", "/api/v1/dns/agents/register") is False
    assert scope_matches_request(["agent"], "POST", "/api/v1/dns/agents/register") is True
    assert scope_matches_request(["dhcp:write"], "POST", "/api/v1/dhcp/agents/x") is False


@pytest.mark.parametrize(
    ("scope", "inside", "outside"),
    [
        ("ipam:write", "/api/v1/ipam/subnets", "/api/v1/ipamx/subnets"),
        ("ipam:write", "/api/v1/vlans", "/api/v1/vlans-extra"),
        ("ipam:write", "/api/v1/vrfs/abc", "/api/v1/vrfsx"),
        ("ipam:write", "/api/v1/network-devices/abc", "/api/v1/network-devices2"),
        ("dhcp:write", "/api/v1/dhcp/scopes", "/api/v1/dhcpx/scopes"),
        ("agent", "/api/v1/dns/agents/heartbeat", "/api/v1/dns/agentsx"),
    ],
)
def test_every_prefix_respects_the_segment_boundary(scope: str, inside: str, outside: str) -> None:
    assert scope_matches_request([scope], "POST", inside) is True
    assert scope_matches_request([scope], "POST", outside) is False


def test_read_scope_mcp_post_respects_the_segment_boundary() -> None:
    assert scope_matches_request(["read"], "POST", "/api/v1/ai/mcp") is True
    assert scope_matches_request(["read"], "POST", "/api/v1/ai/mcpx") is False


# ── Route table: every mounted route against every write scope ──────────

_SCOPE_OWNERS: dict[str, set[str]] = {
    "ipam:write": {"ipam", "vlans", "vrfs", "network-devices"},
    "dns:write": {"dns"},
    "dhcp:write": {"dhcp"},
}


def _mounted_paths() -> set[str]:
    from app.main import app  # noqa: PLC0415

    # The OpenAPI document, not ``app.routes``: included routers are nested
    # objects there, while the document lists every path the app serves.
    return {p for p in app.openapi()["paths"] if p.startswith("/api/v1/")}


def test_write_scopes_grant_only_their_own_top_level_segments() -> None:
    """For every mounted route, a write scope matches if and only if the
    route's first segment under ``/api/v1`` is one the scope names (agent
    paths excepted, which need ``agent``)."""
    paths = _mounted_paths()
    assert any(p.startswith("/api/v1/dnsbl/") for p in paths)
    assert any(p.startswith("/api/v1/dns-threat/") for p in paths)
    wrong: list[str] = []
    for path in sorted(paths):
        segment = path[len("/api/v1/") :].split("/", 1)[0]
        is_agent = path.startswith(("/api/v1/dns/agents/", "/api/v1/dhcp/agents/"))
        for scope, owners in _SCOPE_OWNERS.items():
            expected = segment in owners and not is_agent
            if scope_matches_request([scope], "POST", path) is not expected:
                wrong.append(f"{scope} {path} -> expected {expected}")
    assert not wrong, "\n".join(wrong)


# ── HTTP: a dns:write token is refused on the sibling mounts ─────────────


async def _dns_write_token(db: AsyncSession) -> str:
    owner = User(
        username=f"tok-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Token Owner",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(owner)
    await db.flush()
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=["dns:write"],
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    db.add(FeatureModule(id="security.dnsbl", enabled=True))
    db.add(FeatureModule(id="security.dns_threat", enabled=True))
    await db.flush()
    await db.commit()
    return raw


@pytest.mark.asyncio
async def test_dns_write_token_is_refused_on_dnsbl_and_dns_threat(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    raw = await _dns_write_token(db_session)
    hdr = {"Authorization": f"Bearer {raw}"}

    r = await client.post(
        "/api/v1/dnsbl/lists",
        json={"name": "probe", "zone_suffix": "probe.example.test"},
        headers=hdr,
    )
    assert r.status_code == 403, r.text
    assert "scope" in r.text.lower()

    r = await client.post(
        "/api/v1/dns-threat/mutes",
        json={"client_ip": "10.0.0.1", "reason": "probe"},
        headers=hdr,
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_dns_write_token_still_reaches_the_dns_surface(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Positive control: the same token is not refused by the scope gate on
    ``/api/v1/dns``."""
    raw = await _dns_write_token(db_session)
    r = await client.post(
        "/api/v1/dns/groups",
        json={"name": f"g-{uuid.uuid4().hex[:6]}"},
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code == 201, r.text
