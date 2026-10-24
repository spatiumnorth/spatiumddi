"""Appliance LLDP — renderer + bundle + settings API (issue #343).

The renderer is deterministic over an in-memory ``PlatformSettings`` row
(no DB). The settings-API tests drive the real ``PUT /api/v1/settings``
round-trip + the LLDP field validators.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.appliance.lldp import (
    lldp_bundle,
    render_lldpd_conf,
    render_lldpd_daemon_args,
)

_DEFAULT_IFACE = "eth*,en*,!docker*,!veth*,!br-*,!cni0,!flannel.1"


def _bare_settings() -> PlatformSettings:
    s = PlatformSettings(id=1)
    s.lldp_enabled = True
    s.lldp_tx_interval = 30
    s.lldp_tx_hold = 4
    s.lldp_protocols = []
    s.lldp_interface_pattern = _DEFAULT_IFACE
    s.lldp_management_pattern = ""
    s.lldp_sys_name = ""
    s.lldp_sys_description = ""
    s.lldp_med_location = {}
    s.lldp_snmp_agentx = False
    return s


# ── Renderer ────────────────────────────────────────────────────────────


def test_renders_core_directives() -> None:
    s = _bare_settings()
    out = render_lldpd_conf(s)
    assert "configure lldp tx-interval 30" in out
    assert "configure lldp tx-hold 4" in out
    # Interface allowlist always emitted (excludes container vNICs).
    assert f"configure system interface pattern {_DEFAULT_IFACE}" in out
    assert "configure lldp management-addresses-advertisements" in out.splitlines()
    assert "configure lldp capabilities-advertisements" in out.splitlines()
    # No mgmt pattern / hostname / description lines when those are empty.
    assert "ip management pattern" not in out
    assert "configure system hostname" not in out
    assert "configure system description" not in out


def test_renders_optional_overrides() -> None:
    s = _bare_settings()
    s.lldp_sys_name = "core-rtr1"
    s.lldp_sys_description = "SpatiumDDI Appliance"
    s.lldp_management_pattern = "eth0"
    out = render_lldpd_conf(s)
    assert "configure system hostname core-rtr1" in out
    assert 'configure system description "SpatiumDDI Appliance"' in out
    assert "configure system ip management pattern eth0" in out


def test_tx_falsy_falls_back_to_default() -> None:
    # The API validator enforces 1..3600 / 1..100, so 0 can't actually
    # persist; the renderer's ``or 30`` / ``or 4`` defensively defaults a
    # falsy value rather than emitting a 0 that would disable advertising.
    s = _bare_settings()
    s.lldp_tx_interval = 0
    s.lldp_tx_hold = 0
    out = render_lldpd_conf(s)
    assert "configure lldp tx-interval 30" in out
    assert "configure lldp tx-hold 4" in out


def test_daemon_args_flags_in_deterministic_order() -> None:
    s = _bare_settings()
    s.lldp_protocols = ["sonmp", "cdp"]  # unordered input
    assert render_lldpd_daemon_args(s) == "-c -s"  # cdp, edp, fdp, sonmp order
    s.lldp_protocols = []
    assert render_lldpd_daemon_args(s) == ""


def test_agentx_appends_x_flag() -> None:
    s = _bare_settings()
    s.lldp_protocols = ["cdp"]
    assert render_lldpd_daemon_args(s) == "-c"
    s.lldp_snmp_agentx = True
    assert render_lldpd_daemon_args(s) == "-c -x"  # issue #348
    s.lldp_protocols = []
    assert render_lldpd_daemon_args(s) == "-x"


def test_med_elin_renders() -> None:
    s = _bare_settings()
    assert "med location" not in render_lldpd_conf(s)  # none by default
    s.lldp_med_location = {"elin": "911"}
    assert "configure med location elin 911" in render_lldpd_conf(s)


def test_renderer_is_deterministic() -> None:
    s = _bare_settings()
    s.lldp_protocols = ["cdp"]
    assert render_lldpd_conf(s) == render_lldpd_conf(s)
    assert render_lldpd_daemon_args(s) == render_lldpd_daemon_args(s)


def test_bundle_enabled_vs_disabled() -> None:
    s = _bare_settings()
    s.lldp_protocols = ["cdp"]
    b = lldp_bundle(s)
    assert b["enabled"] is True
    assert b["config_hash"]
    assert "configure lldp tx-interval 30" in b["lldpd_conf"]
    assert b["daemon_args"] == "-c"

    s.lldp_enabled = False
    d = lldp_bundle(s)
    # Stable key set, all empty when disabled.
    assert set(d) == set(b)
    assert d["enabled"] is False
    assert d["config_hash"] == ""
    assert d["lldpd_conf"] == ""
    assert d["daemon_args"] == ""


def test_bundle_hash_shifts_on_protocol_change() -> None:
    s = _bare_settings()
    h0 = lldp_bundle(s)["config_hash"]
    s.lldp_protocols = ["cdp"]
    h1 = lldp_bundle(s)["config_hash"]
    # daemon_args change alone (conf body unchanged) still shifts the hash.
    assert h0 != h1


# ── Settings API ──────────────────────────────────────────────────────────


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_settings_lldp_round_trip(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin_headers(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=h,
        json={
            "lldp_enabled": True,
            "lldp_tx_interval": 45,
            "lldp_tx_hold": 3,
            "lldp_protocols": ["cdp", "cdp", "edp"],  # de-duped by validator
            "lldp_interface_pattern": "eth*,!docker*",
            "lldp_sys_name": "edge1",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lldp_enabled"] is True
    assert body["lldp_tx_interval"] == 45
    assert body["lldp_protocols"] == ["cdp", "edp"]
    assert body["lldp_interface_pattern"] == "eth*,!docker*"
    assert body["lldp_sys_name"] == "edge1"

    # GET reflects the persisted values.
    g = await client.get("/api/v1/settings", headers=h)
    assert g.json()["lldp_tx_interval"] == 45


async def test_settings_lldp_validators(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin_headers(db_session)
    # tx_interval out of range.
    assert (
        await client.put("/api/v1/settings", headers=h, json={"lldp_tx_interval": 99999})
    ).status_code == 422
    # bogus protocol.
    assert (
        await client.put("/api/v1/settings", headers=h, json={"lldp_protocols": ["bogus"]})
    ).status_code == 422
    # config-injection chars in the interface pattern.
    assert (
        await client.put(
            "/api/v1/settings", headers=h, json={"lldp_interface_pattern": "eth0; rm -rf /"}
        )
    ).status_code == 422
    # control char in the system name.
    assert (
        await client.put("/api/v1/settings", headers=h, json={"lldp_sys_name": "a\nb"})
    ).status_code == 422
    # non-numeric MED ELIN (issue #348).
    assert (
        await client.put(
            "/api/v1/settings", headers=h, json={"lldp_med_location": {"elin": "nope"}}
        )
    ).status_code == 422


async def test_settings_lldp_agentx_and_elin_round_trip(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=h,
        json={"lldp_snmp_agentx": True, "lldp_med_location": {"elin": "911"}},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lldp_snmp_agentx"] is True
    assert body["lldp_med_location"] == {"elin": "911"}


def test_no_rendered_line_ends_in_a_bare_enable_or_disable() -> None:
    """lldpcli takes these toggles with no argument (``unconfigure`` turns
    them off); a trailing ``enable`` is refused at every lldpd start (#2576)."""
    s = _bare_settings()
    s.lldp_sys_name = "core-rtr1"
    s.lldp_management_pattern = "10.0.0.0/24"
    s.lldp_med_location = {"elin": "5551234567"}
    for line in render_lldpd_conf(s).splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        assert line.split()[-1] not in {"enable", "disable"}, line
