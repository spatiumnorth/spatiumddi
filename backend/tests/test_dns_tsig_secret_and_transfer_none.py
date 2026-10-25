"""TSIG key secrets are one base64 string; ``none`` keeps its meaning in allow-transfer.

* A key's secret is written verbatim into the agent's key file as
  ``secret "…";``, so the API accepts only a base64 value of a usable length
  on create, refuses a secret on update (that is what rotate is for), and the
  bundle leaves out a stored row whose secret is not one base64 string.
* BIND reads ``none`` in an address-match list as "deny everyone from here
  on". A list that combines it with other entries has two plausible readings,
  so ``allow_transfer`` refuses it on both the group options and a zone.
"""

from __future__ import annotations

import base64

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.dns import DNSTSIGKey
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.named_conf_validation import ViewValidationError, validate_server_option
from app.services.dns.tsig import resolve_group_transfer_key, tsig_secret_problem
from tests.test_dns_server_group_move import _auth, _group, _server, _superadmin

_GOOD = base64.b64encode(b"k" * 32).decode()
_INJECTED = 'AAAA"; }; key "evil" { algorithm hmac-sha256; secret "QUFBQQ=='


def _url(gid: object) -> str:
    return f"/api/v1/dns/groups/{gid}/tsig-keys"


# ── secrets ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "secret",
    [
        "not base64!",
        _INJECTED,
        "c2VjcmV0 c2VjcmV0c2VjcmV0",
        base64.b64encode(b"short").decode(),  # 5 bytes
        base64.b64encode(b"x" * 600).decode(),
        "QUFBQQ",  # missing padding
        "",
    ],
)
def test_secret_problem_refuses(secret: str) -> None:
    assert tsig_secret_problem(secret) is not None


@pytest.mark.parametrize("n", [16, 32, 64, 512])
def test_secret_problem_accepts_base64_of_a_usable_length(n: int) -> None:
    assert tsig_secret_problem(base64.b64encode(b"k" * n).decode()) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("secret", ["not base64!", _INJECTED, base64.b64encode(b"tiny").decode()])
async def test_create_refuses_a_malformed_secret(
    client: AsyncClient, db_session: AsyncSession, secret: str
) -> None:
    token = await _superadmin(db_session, "rsec1")
    g = await _group(db_session, "gsec1")
    r = await client.post(_url(g.id), json={"name": "xfer", "secret": secret}, headers=_auth(token))
    assert r.status_code == 422, r.text
    assert "secret" in r.text


@pytest.mark.asyncio
async def test_create_accepts_base64_and_generates_when_blank(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "rsec2")
    g = await _group(db_session, "gsec2")
    r = await client.post(
        _url(g.id), json={"name": "given", "secret": f"  {_GOOD}\n"}, headers=_auth(token)
    )
    assert r.status_code == 201, r.text
    assert r.json()["secret"] == _GOOD
    r = await client.post(_url(g.id), json={"name": "made", "secret": "  "}, headers=_auth(token))
    assert r.status_code == 201, r.text
    assert tsig_secret_problem(r.json()["secret"]) is None


@pytest.mark.asyncio
async def test_update_refuses_a_secret_instead_of_ignoring_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "rsec3")
    g = await _group(db_session, "gsec3")
    made = await client.post(_url(g.id), json={"name": "k1"}, headers=_auth(token))
    assert made.status_code == 201, made.text
    key_url = f"{_url(g.id)}/{made.json()['id']}"
    r = await client.put(key_url, json={"secret": _INJECTED}, headers=_auth(token))
    assert r.status_code == 422, r.text
    r = await client.put(key_url, json={"notes": "fine"}, headers=_auth(token))
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_bundle_leaves_out_a_stored_malformed_secret(db_session: AsyncSession) -> None:
    g = await _group(db_session, "gsec4")
    s = await _server(db_session, g, "ns1", is_primary=True)
    db_session.add_all(
        [
            DNSTSIGKey(
                group_id=g.id,
                name="aaa-bad",
                algorithm="hmac-sha256",
                secret_encrypted=encrypt_str(_INJECTED),
            ),
            DNSTSIGKey(
                group_id=g.id,
                name="bbb-good",
                algorithm="hmac-sha256",
                secret_encrypted=encrypt_str(_GOOD),
            ),
        ]
    )
    await db_session.flush()

    bundle = await build_config_bundle(db_session, s)
    assert [k["name"] for k in bundle["tsig_keys"]] == ["bbb-good"]
    # The transfer key the control plane signs with agrees with what shipped.
    chosen = await resolve_group_transfer_key(db_session, g.id)
    assert chosen is not None and chosen.name == "bbb-good"


# ── allow_transfer ``none`` ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [["none", "10.0.0.0/8"], ["10.0.0.0/8", "none"], ["NONE", "any"], ["!none", "10.0.0.0/8"]],
)
def test_allow_transfer_refuses_none_mixed_with_other_entries(value: list[str]) -> None:
    with pytest.raises(ViewValidationError) as info:
        validate_server_option("allow_transfer", value)
    assert info.value.field == "allow_transfer"
    assert info.value.value.lstrip("!").lower() == "none"


@pytest.mark.parametrize("value", [["none"], ["10.0.0.0/8"], ["any"], ["10.0.0.0/8", "!192.0.2.1"]])
def test_allow_transfer_accepts_lists_with_one_reading(value: list[str]) -> None:
    assert validate_server_option("allow_transfer", value) == value


def test_other_lists_keep_accepting_none_beside_entries() -> None:
    """Only allow_transfer is narrowed here."""
    assert validate_server_option("allow_query", ["none", "10.0.0.0/8"]) == ["none", "10.0.0.0/8"]


@pytest.mark.asyncio
async def test_options_and_zone_endpoints_refuse_a_mixed_none_list(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "rsec5")
    g = await _group(db_session, "gsec5")
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{g.id}/options",
        json={"allow_transfer": ["none", "10.0.0.0/8"]},
        headers=_auth(token),
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["field"] == "allow_transfer"

    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones",
        json={"name": "example.com", "allow_transfer": ["10.0.0.0/8", "none"]},
        headers=_auth(token),
    )
    assert r.status_code == 422, r.text

    r = await client.put(
        f"/api/v1/dns/groups/{g.id}/options",
        json={"allow_transfer": ["none"]},
        headers=_auth(token),
    )
    assert r.status_code == 200, r.text
