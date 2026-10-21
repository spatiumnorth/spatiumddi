"""#2295 — an operator TSIG key must never render a second ``key {}`` for a name.

BIND treats ``foo``, ``Foo`` and ``foo.`` as one key, and the group's own
generated key is ``spatium-<label>``. A duplicate ``key`` statement makes
``named-checkconf`` reject the whole file and the agent decline the bundle,
so the clash is refused at the API and, for rows already stored, the bundle
ships one key per name.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.dns import DNSTSIGKey
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.tsig import set_group_tsig_secret
from tests.test_dns_server_group_move import _auth, _group, _server, _superadmin

_B64 = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE="


def _url(gid: object) -> str:
    return f"/api/v1/dns/groups/{gid}/tsig-keys"


def normalize_tsig_name(n: str) -> str:
    """BIND's view of a key name (kept local so the test states the rule itself)."""
    return n.strip().lower().rstrip(".")


@pytest.mark.asyncio
async def test_trailing_dot_twin_is_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _superadmin(db_session, "r2295a")
    g = await _group(db_session, "g2295a")
    ok = await client.post(_url(g.id), json={"name": "foo"}, headers=_auth(token))
    assert ok.status_code == 201, ok.text
    r = await client.post(_url(g.id), json={"name": "foo."}, headers=_auth(token))
    assert r.status_code in (409, 422), r.text
    assert "foo" in r.json()["detail"]
    # and the other direction
    ok2 = await client.post(_url(g.id), json={"name": "bar."}, headers=_auth(token))
    assert ok2.status_code == 201
    r2 = await client.post(_url(g.id), json={"name": "BAR"}, headers=_auth(token))
    assert r2.status_code in (409, 422), r2.text


@pytest.mark.asyncio
async def test_group_key_name_and_reserved_prefix_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "r2295b")
    g = await _group(db_session, "g2295b", tsig_key_name="legacy-name")
    set_group_tsig_secret(g, _B64)
    await db_session.flush()
    for name in ("spatium-g2295b", "spatium-anything.", "legacy-name", "legacy-name."):
        r = await client.post(_url(g.id), json={"name": name}, headers=_auth(token))
        assert r.status_code == 422, (name, r.text)
        assert name.rstrip(".") in r.json()["detail"] or "reserved" in r.json()["detail"]


@pytest.mark.asyncio
async def test_rename_into_a_clash_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "r2295c")
    g = await _group(db_session, "g2295c")
    a = await client.post(_url(g.id), json={"name": "aaa"}, headers=_auth(token))
    b = await client.post(_url(g.id), json={"name": "bbb"}, headers=_auth(token))
    assert a.status_code == b.status_code == 201
    r = await client.put(
        f"{_url(g.id)}/{b.json()['id']}", json={"name": "aaa."}, headers=_auth(token)
    )
    assert r.status_code in (409, 422), r.text
    r = await client.put(
        f"{_url(g.id)}/{b.json()['id']}", json={"name": "spatium-x"}, headers=_auth(token)
    )
    assert r.status_code == 422, r.text
    # re-saving a key under its own name still works
    r = await client.put(
        f"{_url(g.id)}/{b.json()['id']}", json={"name": "bbb", "notes": "n"}, headers=_auth(token)
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_bundle_never_ships_two_keys_for_one_name(db_session: AsyncSession) -> None:
    """Rows stored before the API refused the clash render once, deterministically."""
    g = await _group(db_session, "g2295d", tsig_key_name="spatium-g2295d")
    set_group_tsig_secret(g, _B64)
    s = await _server(db_session, g, "ns1", is_primary=True)
    for name in ("spatium-g2295d", "foo", "foo.", "FOO", "zzz"):
        db_session.add(
            DNSTSIGKey(
                group_id=g.id,
                name=name,
                algorithm="hmac-sha256",
                secret_encrypted=encrypt_str(_B64),
            )
        )
    await db_session.flush()

    bundle = await build_config_bundle(db_session, s)
    names = [k["name"] for k in bundle["tsig_keys"]]
    assert len({normalize_tsig_name(n) for n in names}) == len(names), names
    assert names[0] == "spatium-g2295d"  # the loopback identity stays first
    assert sorted(names[1:]) in (["FOO", "zzz"], ["foo", "zzz"], ["foo.", "zzz"])
    assert len(names) == 3
