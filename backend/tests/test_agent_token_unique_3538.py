"""#3538 — two agent tokens minted in the same second must differ.

Staleness is judged by comparing the stored ``agent_jwt_hash`` with the
presented token's hash. ``exp`` has whole-second resolution and the claims
are otherwise the same for one server, so a replacement token minted in the
same second as the one it replaces was byte-identical to it: the displaced
agent's token still passed (the flaky #2219 duplicate-pair test).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as dns_agents_api
from app.config import settings
from app.models.dns import DNSServer
from app.services.dhcp import agent_token as dhcp_tok
from app.services.dns import agent_token as dns_tok
from app.services.looking_glass import agent_token as lg_tok

# One instant, captured from the real clock at import, so both mints share a
# second but the tokens' ``exp`` (mint time + TTL) stays in the future when
# ``verify_agent_token`` checks it against the real clock (#3658). A fixed
# calendar date expired a day after it was written.
_NOW = datetime.now(UTC).replace(microsecond=123456)


class _Frozen(datetime):
    @classmethod
    def now(cls, tz=None):  # type: ignore[no-untyped-def]
        return _NOW


@pytest.mark.parametrize("mod", [dns_tok, dhcp_tok, lg_tok])
def test_same_second_tokens_differ(mod, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(mod, "datetime", _Frozen)
    t1, _ = mod.mint_agent_token("srv", "agent", "fp")
    t2, _ = mod.mint_agent_token("srv", "agent", "fp")
    assert t1 != t2
    assert mod.hash_token(t1) != mod.hash_token(t2)
    mod.verify_agent_token(t1)
    mod.verify_agent_token(t2)


def _legacy_token(mod, token: str) -> str:  # type: ignore[no-untyped-def]
    """The same claims minted the pre-#3538 way: no ``jti``."""
    claims = mod.verify_agent_token(token)
    claims.pop("jti")
    return jwt.encode(claims, settings.secret_key, algorithm=mod.ALGORITHM)


@pytest.mark.parametrize("mod", [dns_tok, dhcp_tok, lg_tok])
def test_a_token_minted_before_the_jti_still_verifies(mod) -> None:  # type: ignore[no-untyped-def]
    token, _ = mod.mint_agent_token("srv", "agent", "fp")
    legacy = _legacy_token(mod, token)
    assert "jti" not in mod.verify_agent_token(legacy)


@pytest.mark.asyncio
async def test_an_agent_holding_a_pre_upgrade_token_keeps_working(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An agent upgraded across #3538 still presents the jti-less token it
    cached; the stored hash is of that token, so it must keep authenticating
    and must still be rotated onto a new (jti-carrying) token."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-3538")
    agent_id = str(uuid.uuid4())
    r = await client.post(
        "/api/v1/dns/agents/register",
        headers={"X-DNS-Agent-Key": "psk-3538"},
        json={
            "hostname": "ns-3538",
            "driver": "bind9",
            "roles": ["authoritative"],
            "group_name": f"g3538-{uuid.uuid4().hex[:6]}",
            "fingerprint": "fp-3538",
            "agent_id": agent_id,
            "version": "2026.11.05-1",
        },
    )
    assert r.status_code == 200, r.text
    legacy = _legacy_token(dns_tok, r.json()["agent_token"])

    srv = (
        await db_session.execute(select(DNSServer).where(DNSServer.agent_id == uuid.UUID(agent_id)))
    ).scalar_one()
    srv.agent_jwt_hash = dns_tok.hash_token(legacy)
    await db_session.commit()

    monkeypatch.setattr(dns_agents_api, "needs_rotation", lambda payload: True)
    r = await client.post(
        "/api/v1/dns/agents/heartbeat",
        headers={"Authorization": f"Bearer {legacy}"},
        json={},
    )
    assert r.status_code == 200, r.text
    rotated = r.json()["rotated_token"]
    assert rotated and rotated != legacy
    assert "jti" in dns_tok.verify_agent_token(rotated)
    # The rotation is adopted: the new token authenticates, the old one is stale.
    ok = await client.post(
        "/api/v1/dns/agents/heartbeat", headers={"Authorization": f"Bearer {rotated}"}, json={}
    )
    assert ok.status_code == 200, ok.text
    stale = await client.post(
        "/api/v1/dns/agents/heartbeat", headers={"Authorization": f"Bearer {legacy}"}, json={}
    )
    assert stale.status_code == 401
