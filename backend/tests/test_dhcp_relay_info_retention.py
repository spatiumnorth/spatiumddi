"""#54 — a group with an option-82 class makes Kea keep relay agent information.

A unicast renewal never passes through the relay, so it carries no option 82
and stops matching a ``relay4[...]`` class. Measured on kea-dhcp4 3.0.3: a
lease from a pool restricted to such a class is NAKed at every renewal unless
both ``stash-agent-options`` and ``store-extended-info`` are on (either alone
still NAKs). So the bundle sets ``relay_info_retention`` when any Dhcp4 class
of the group tests option 82, the agent payload carries it in the ``server``
block, and the renderers turn both keys on.

What each test would look like if it broke:

* detection — a hand-written ``relay4`` class with renewals still NAKed, or
  every group flipped on because ``'relay4'`` appeared inside a string;
* the ETag — a group with no such class re-pushed its config on upgrade, or a
  group that gains one never wakes its agents;
* the wire — set in the bundle and hashed, but never shipped (#430 / #858).
"""

from __future__ import annotations

import json
import types
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dhcp import base as dhcp_base
from app.drivers.dhcp.base import (
    ClientClassDef,
    ConfigBundle,
    PoolDef,
    ScopeDef,
    ServerOptionsDef,
)
from app.drivers.dhcp.kea import KeaDriver
from app.models.dhcp import DHCPClientClass
from app.services.dhcp import agent_token as dhcp_tokens
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.option_validation import (
    relay_info_retention,
    uses_relay_agent_info,
)
from tests.test_dhcp_phone_profiles import _make_group_server_scope

KEYS = ("stash-agent-options", "store-extended-info")


# ── detection ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expr",
    [
        "relay4[1].hex == 0x657468302F313A313030",
        "substring(relay4[2].hex, 0, 3) == 0xAABBCC",
        "relay4[6].exists",
        "not relay4[9].exists",
        # What a structured match (match_spec) compiles to: parenthesised terms.
        "(relay4[1].hex == 0x0A0B) and (substring(relay4[2].hex, -3, all) == 0x0A0B0C)",
        "option[82].option[1].hex == 0x0A0B",
        "option[dhcp-agent-options].exists",
        "option[ 82 ].exists",
        "pkt4.mac == 0x020000000001 or relay4[1].hex == 'sw1'",
    ],
)
def test_option_82_tests_are_detected(expr: str) -> None:
    assert uses_relay_agent_info(expr)


@pytest.mark.parametrize(
    "expr",
    [
        "",
        None,
        "option[60].text == 'relay4'",
        "option[60].text == 'option[82]'",
        "pkt4.mac == 0x020000000001",
        "option[182].exists",
        "option[8].exists",
        "member('relay4-users')",
        "relay6[0].option[18].exists",
    ],
)
def test_other_tests_are_not(expr: str | None) -> None:
    assert not uses_relay_agent_info(expr)


def test_only_classes_rendered_into_dhcp4_count() -> None:
    v6 = ClientClassDef(name="v6", match_expression="relay4[1].exists", address_family="ipv6")
    v4 = ClientClassDef(name="v4", match_expression="relay4[1].exists", address_family="ipv4")
    plain = ClientClassDef(name="p", match_expression="pkt4.mac == 0x02")
    assert not relay_info_retention([v6, plain])
    assert relay_info_retention([plain, v4])
    assert not relay_info_retention([])


# ── bundle: ETag + preview render ───────────────────────────────────────


def _bundle(**kw: Any) -> ConfigBundle:
    return ConfigBundle(
        server_id="00000000-0000-0000-0000-000000000054",
        server_name="kea-54",
        driver="kea",
        roles=(),
        options=ServerOptionsDef(options={}, lease_time=3600),
        scopes=(
            ScopeDef(
                subnet_cidr="10.54.0.0/24",
                pools=(PoolDef(start_ip="10.54.0.100", end_ip="10.54.0.200"),),
            ),
            ScopeDef(
                subnet_cidr="2001:db8:54::/64",
                address_family="ipv6",
                pools=(PoolDef(start_ip="2001:db8:54::10", end_ip="2001:db8:54::20"),),
            ),
        ),
        client_classes=(),
        generated_at=datetime(2026, 11, 21, tzinfo=UTC),
        **kw,
    )


def _hashed_payload(bundle: ConfigBundle, monkeypatch: pytest.MonkeyPatch) -> dict:
    """The dict ``compute_etag`` hashes."""
    seen: list[dict] = []

    def dumps(obj: Any, **kw: Any) -> str:
        seen.append(obj)
        return json.dumps(obj, **kw)

    monkeypatch.setattr(dhcp_base, "json", types.SimpleNamespace(dumps=dumps))
    bundle.compute_etag()
    monkeypatch.undo()
    return seen[-1]


def test_etag_input_unchanged_without_an_option_82_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The key is hashed only when set, so no group without such a class sees
    its ETag move (and its agents re-pushed) on upgrade."""
    assert "relay_info_retention" not in _hashed_payload(_bundle(), monkeypatch)
    assert _hashed_payload(_bundle(relay_info_retention=True), monkeypatch)["relay_info_retention"]


def test_retention_shifts_the_etag() -> None:
    """Adding the group's first option-82 class must wake its agents."""
    assert _bundle().compute_etag() != _bundle(relay_info_retention=True).compute_etag()


def test_preview_renders_both_keys_in_dhcp4_only() -> None:
    doc = json.loads(KeaDriver().render_config(_bundle(relay_info_retention=True)))
    assert {k: doc["Dhcp4"].get(k) for k in KEYS} == dict.fromkeys(KEYS, True)
    assert not set(KEYS) & set(doc["Dhcp6"])


def test_preview_unchanged_without_retention() -> None:
    doc = json.loads(KeaDriver().render_config(_bundle()))
    assert not set(KEYS) & set(doc["Dhcp4"])


# ── build_config_bundle: classes → flag ─────────────────────────────────


async def _class(db: AsyncSession, group_id: uuid.UUID, expr: str, family: str = "ipv4") -> None:
    db.add(
        DHCPClientClass(
            group_id=group_id,
            name=f"c-{uuid.uuid4().hex[:6]}",
            match_expression=expr,
            address_family=family,
        )
    )
    await db.flush()


async def test_hand_written_relay4_class_turns_retention_on(db_session: AsyncSession) -> None:
    """Existing classes are covered, not only the #54 builder's: an operator
    who restricted a pool to a hand-written relay4 test has had every renewal
    NAKed until now."""
    grp, srv, _ = await _make_group_server_scope(db_session)
    await _class(db_session, grp.id, "pkt4.mac == 0x020000000001")
    assert (await build_config_bundle(db_session, srv)).relay_info_retention is False

    await _class(db_session, grp.id, "substring(relay4[2].hex, 0, 3) == 0xAABBCC")
    assert (await build_config_bundle(db_session, srv)).relay_info_retention is True


async def test_relay4_inside_a_literal_or_a_v6_class_does_not(
    db_session: AsyncSession,
) -> None:
    grp, srv, _ = await _make_group_server_scope(db_session)
    await _class(db_session, grp.id, "option[60].text == 'relay4'")
    await _class(db_session, grp.id, "relay6[0].option[18].exists", family="ipv6")
    assert (await build_config_bundle(db_session, srv)).relay_info_retention is False


# ── agent wire payload ──────────────────────────────────────────────────


async def _poll(client: AsyncClient, db: AsyncSession, srv: Any) -> dict:
    srv.agent_id = uuid.uuid4()
    srv.agent_registered = True
    srv.agent_approved = True
    srv.agent_fingerprint = "fp"
    token, _exp = dhcp_tokens.mint_agent_token(
        server_id=str(srv.id), agent_id=str(srv.agent_id), fingerprint="fp"
    )
    srv.agent_token_hash = dhcp_tokens.hash_token(token)
    await db.commit()
    resp = await client.get(
        "/api/v1/dhcp/agents/config", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["bundle"]["server"]


async def test_the_agent_payload_carries_the_flag(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Shipped, not only hashed (#430, #858): the agent renders the keys from
    the ``server`` block."""
    grp, srv, _ = await _make_group_server_scope(db_session)
    await _class(db_session, grp.id, "relay4[1].hex == 0x0A0B")
    assert (await _poll(client, db_session, srv))["relay_info_retention"] is True


async def test_the_agent_payload_omits_it_otherwise(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Absent rather than ``false``, so a group with no option-82 class gets
    the same wire bundle as before."""
    _grp, srv, _ = await _make_group_server_scope(db_session)
    assert "relay_info_retention" not in await _poll(client, db_session, srv)
