"""Operator text written into line-oriented appliance host configs.

snmpd.conf, chrony.conf, apt's sources.list and the nftables drop-in all end
a directive at the newline. Each value an operator types that lands in one of
them is checked twice:

* at the API, which answers 422 naming the field; and
* in the renderer, for rows stored before the API check existed.

The renderer tests assert on the rendered file, not on an exit code: what
matters is that no extra directive line comes out.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.firewall import FirewallPolicy, FirewallRule
from app.models.settings import DEFAULT_APT_SOURCES, PlatformSettings
from app.services.appliance.apt import render_sources_list
from app.services.appliance.firewall_merge import (
    compile_firewall_from_policies,
    policy_set_from_orm,
)
from app.services.appliance.ntp import render_chrony_conf
from app.services.appliance.snmp import render_snmpd_conf

CONTROL_CASES = [
    pytest.param("ops\nrwcommunity qa-example default", id="newline"),
    pytest.param("ops\rrwcommunity qa-example default", id="carriage-return"),
    pytest.param("ops\x00rwcommunity", id="nul"),
]


async def _superadmin_token(db: AsyncSession) -> str:
    u = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return create_access_token(str(u.id))


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _directive_lines(text: str) -> list[str]:
    """Every line that is not blank and not a comment, i.e. every line the
    daemon reads as a directive."""
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _snmp(**kw) -> PlatformSettings:
    s = PlatformSettings(id=0)
    s.snmp_enabled = True
    s.snmp_version = kw.get("version", "v2c")
    s.snmp_community_encrypted = encrypt_str(kw.get("community", "public"))
    s.snmp_allowed_sources = kw.get("sources", ["10.0.0.0/8"])
    s.snmp_v3_users = kw.get("v3_users", [])
    s.snmp_sys_contact = kw.get("contact", "")
    s.snmp_sys_location = kw.get("location", "")
    return s


# ── SNMP: API boundary ───────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["snmp_sys_contact", "snmp_sys_location"])
@pytest.mark.parametrize("value", CONTROL_CASES)
async def test_put_refuses_control_chars_in_snmp_sys_text(
    client: AsyncClient, db_session: AsyncSession, field: str, value: str
) -> None:
    token = await _superadmin_token(db_session)
    r = await client.put("/api/v1/settings", headers=_hdr(token), json={field: value})
    assert r.status_code == 422, r.text
    assert field in r.text


@pytest.mark.asyncio
async def test_put_accepts_ordinary_snmp_sys_text(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin_token(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={"snmp_sys_contact": 'NOC "on call" <noc@example.test>', "snmp_sys_location": "DC1"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["snmp_sys_contact"] == 'NOC "on call" <noc@example.test>'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [*CONTROL_CASES, pytest.param("public default", id="space")],
)
async def test_put_refuses_an_snmp_community_that_splits_its_line(
    client: AsyncClient, db_session: AsyncSession, value: str
) -> None:
    token = await _superadmin_token(db_session)
    r = await client.put("/api/v1/settings", headers=_hdr(token), json={"snmp_community": value})
    assert r.status_code == 422, r.text
    assert "snmp_community" in r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("which", ["auth_pass", "priv_pass"])
async def test_put_refuses_control_chars_in_a_v3_passphrase(
    client: AsyncClient, db_session: AsyncSession, which: str
) -> None:
    token = await _superadmin_token(db_session)
    user = {
        "username": "ops",
        "auth_protocol": "SHA",
        "auth_pass": "longenough1",
        "priv_protocol": "AES",
        "priv_pass": "longenough2",
    }
    user[which] = 'pass"\nrwuser evil .1'
    r = await client.put("/api/v1/settings", headers=_hdr(token), json={"snmp_v3_users": [user]})
    assert r.status_code == 422, r.text
    assert which in r.text


def test_v3_username_guard_is_unchanged() -> None:
    from app.api.v1.settings.router import SNMPV3UserUpdate

    with pytest.raises(ValidationError):
        SNMPV3UserUpdate(username="ops\nrwuser evil .1")
    with pytest.raises(ValidationError):
        SNMPV3UserUpdate(username="ops ro")
    assert SNMPV3UserUpdate(username=" monitoring-ro_1 ").username == "monitoring-ro_1"


# ── SNMP: renderer, for values already stored ────────────────────────


@pytest.mark.parametrize("value", CONTROL_CASES)
@pytest.mark.parametrize("field", ["contact", "location"])
def test_stored_sys_text_with_control_chars_adds_no_directive(field: str, value: str) -> None:
    text = render_snmpd_conf(_snmp(**{field: value}))
    directives = _directive_lines(text)
    assert not any("rwcommunity" in ln for ln in directives), text
    # The line is left out entirely; everything else still renders.
    assert not any(ln.startswith(("sysContact", "sysLocation")) for ln in directives)
    assert "rocommunity public 10.0.0.0/8" in directives
    assert "\r" not in text and "\x00" not in text


def test_the_reported_shape_renders_no_second_directive() -> None:
    text = render_snmpd_conf(_snmp(contact="ops\nrwcommunity qa-example default"))
    assert "rwcommunity qa-example default" not in text.replace("# ", "")
    assert all(not ln.startswith("rwcommunity") for ln in text.splitlines())


def test_ordinary_sys_text_still_renders_byte_for_byte() -> None:
    text = render_snmpd_conf(_snmp(contact="noc@example.test", location="DC1 rack 4"))
    assert 'sysContact     "noc@example.test"' in text.splitlines()
    assert 'sysLocation    "DC1 rack 4"' in text.splitlines()


@pytest.mark.parametrize("community", ["pub\nrwcommunity evil default", "pub default"])
def test_stored_community_that_splits_its_line_is_not_published(community: str) -> None:
    text = render_snmpd_conf(_snmp(community=community))
    directives = _directive_lines(text)
    assert not any(ln.startswith(("rocommunity", "rwcommunity")) for ln in directives), text


def test_stored_source_that_is_not_a_network_is_dropped() -> None:
    text = render_snmpd_conf(_snmp(sources=["10.0.0.0/8", "10.1.0.0/16\nrwcommunity x default"]))
    directives = _directive_lines(text)
    assert "rocommunity public 10.0.0.0/8" in directives
    assert not any("rwcommunity" in ln for ln in directives), text


def test_stored_v3_passphrase_with_a_newline_omits_the_user() -> None:
    text = render_snmpd_conf(
        _snmp(
            version="v3",
            v3_users=[
                {
                    "username": "ops",
                    "auth_protocol": "SHA",
                    "auth_pass_enc": encrypt_str('p"\nrwuser evil .1').decode("ascii"),
                    "priv_protocol": "none",
                    "priv_pass_enc": None,
                }
            ],
        )
    )
    directives = _directive_lines(text)
    assert not any(ln.startswith(("rwuser", "createUser", "rouser")) for ln in directives), text


# ── SNMP + NTP: Operator Copilot write path ──────────────────────────


@pytest.mark.parametrize("value", CONTROL_CASES)
def test_copilot_snmp_args_refuse_control_chars(value: str) -> None:
    from app.services.ai.operations_writes import UpdateSNMPSettingsArgs

    for field in ("sys_contact", "sys_location", "community"):
        with pytest.raises(ValidationError):
            UpdateSNMPSettingsArgs(enabled=True, **{field: value})
    with pytest.raises(ValidationError):
        UpdateSNMPSettingsArgs(enabled=True, allowed_sources=[f"10.0.0.0/8{value}"])
    ok = UpdateSNMPSettingsArgs(enabled=True, allowed_sources=["10.0.0.5/8"])
    assert ok.allowed_sources == ["10.0.0.0/8"]


def test_copilot_ntp_args_refuse_values_that_split_a_line() -> None:
    from app.services.ai.operations_writes import UpdateNTPSettingsArgs

    with pytest.raises(ValidationError):
        UpdateNTPSettingsArgs(source_mode="pool", pool_servers=["a.example\nallow all"])
    with pytest.raises(ValidationError):
        UpdateNTPSettingsArgs(source_mode="pool", allow_client_networks=["10.0.0.0/8\nallow"])
    ok = UpdateNTPSettingsArgs(source_mode="pool", pool_servers=[" a.example "])
    assert ok.pool_servers == ["a.example"]


# ── NTP: API + renderer ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_put_refuses_nul_in_an_ntp_pool_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin_token(db_session)
    r = await client.put(
        "/api/v1/settings", headers=_hdr(token), json={"ntp_pool_servers": ["a.example\x00b"]}
    )
    assert r.status_code == 422, r.text
    assert "ntp_pool_servers" in r.text


def _ntp(**kw) -> PlatformSettings:
    s = PlatformSettings(id=0)
    s.ntp_source_mode = kw.get("mode", "mixed")
    s.ntp_pool_servers = kw.get("pool", ["pool.example"])
    s.ntp_custom_servers = kw.get("custom", [])
    s.ntp_allow_clients = kw.get("allow_clients", False)
    s.ntp_allow_client_networks = kw.get("allow_networks", [])
    return s


def test_stored_ntp_values_with_newlines_add_no_directive() -> None:
    text = render_chrony_conf(
        _ntp(
            pool=["pool.example", "evil.example iburst\nallow all"],
            custom=[{"host": "t.example\nallow 0.0.0.0/0"}],
            allow_clients=True,
            allow_networks=["10.0.0.0/8", "192.0.2.0/24\nallow all"],
        )
    )
    directives = _directive_lines(text)
    assert "pool pool.example iburst" in directives
    assert "allow 10.0.0.0/8" in directives
    assert not any(ln in ("allow all", "allow 0.0.0.0/0") for ln in directives), text
    assert not any("evil.example" in ln or "t.example" in ln for ln in directives)


# ── APT: API + renderer ──────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "trixie\ndeb [trusted=yes] http://mirror.example/ x main",
        "trixie\rdeb [trusted=yes] http://mirror.example/ x main",
        "trixie\x00",
    ],
)
async def test_put_refuses_control_chars_in_apt_suites(
    client: AsyncClient, db_session: AsyncSession, value: str
) -> None:
    token = await _superadmin_token(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={
            "apt_managed": True,
            "apt_sources": [{"uri": "https://mirror.lan/debian", "suites": value}],
        },
    )
    assert r.status_code == 422, r.text
    assert "suites" in r.text


def test_stored_apt_source_with_a_newline_adds_no_entry() -> None:
    s = PlatformSettings(id=0)
    s.apt_sources = [
        dict(DEFAULT_APT_SOURCES[0]),
        {
            "uri": "https://mirror.lan/debian",
            "suites": "trixie\ndeb [trusted=yes] http://mirror.example/ x main",
            "components": "main",
            "enabled": True,
        },
    ]
    text = render_sources_list(s)
    debs = [ln for ln in _directive_lines(text) if ln.startswith("deb ")]
    assert len(debs) == 1, text
    assert "trusted=yes" not in text


# ── Firewall rule comments: API + renderer ───────────────────────────


@pytest.mark.parametrize(
    "comment",
    ['x"\ntcp dport 22 drop comment "y', "a\nb", "a\rb", "a\x00b", 'say "hi"', "back\\slash"],
)
def test_firewall_rule_comment_refuses_line_breaking_text(comment: str) -> None:
    from app.api.v1.appliance.firewall import RuleIn

    with pytest.raises(ValidationError):
        RuleIn(seq=10, protocol="tcp", ports=[8080], comment=comment)
    assert RuleIn(seq=10, protocol="tcp", ports=[8080], comment="app (8080)").comment == (
        "app (8080)"
    )


def test_stored_firewall_comment_with_a_newline_adds_no_rule() -> None:
    rule = FirewallRule(
        seq=10,
        action="accept",
        protocol="tcp",
        ports=[8080],
        source_kind="any",
        source_cidrs=[],
        family="both",
        comment='app"\ntcp dport 22 drop comment "x',
        enabled=True,
    )
    fleet = FirewallPolicy(
        name="fleet", scope_kind="fleet", enabled=True, priority=100, rules=[rule]
    )
    ps = policy_set_from_orm([fleet], [])
    body = compile_firewall_from_policies({"roles": []}, None, policy_set=ps)
    rule_lines = _directive_lines(body)
    assert not any(ln.startswith("tcp dport 22 drop") for ln in rule_lines), body
    overlay = [ln for ln in rule_lines if "8080" in ln]
    assert overlay == ['tcp dport 8080 accept comment "apptcp dport 22 drop comment x"']
