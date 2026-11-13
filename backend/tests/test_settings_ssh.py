"""Settings-router tests for SSH config (issue #157).

Covers:

* PUT persists ssh_* fields (keys + toggles + port + source CIDRs).
* Lockout safety — disabling password auth with zero keys → 422.
* Malformed public key → 422.
* Privileged port (< 1024, not 22) → 422.
* A HOSTCONFIG_ALL wake fires on an ssh_* change.
* A dedicated audit row (resource_id='ssh') is written.
* Permission denial without write:settings → 403.
"""

from __future__ import annotations

import base64

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import PlatformSettings


def _make_ed25519_key(comment: str = "alice@host") -> str:
    name = b"ssh-ed25519"
    key = b"\x00" * 32
    blob = len(name).to_bytes(4, "big") + name + len(key).to_bytes(4, "big") + key
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " " + comment


_ED = _make_ed25519_key()


async def _make_user(db: AsyncSession, *, username: str, superadmin: bool) -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    token = create_access_token(str(user.id))
    return user, token


@pytest.mark.asyncio
async def test_put_persists_ssh_fields(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_user(db_session, username="sshsuper1", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={
            "ssh_authorized_keys": [{"name": "alice", "public_key": _ED, "comment": "laptop"}],
            "ssh_password_auth_enabled": False,
            "ssh_allow_root_login": True,
            "ssh_port": 2222,
            "ssh_allowed_source_networks": ["10.0.0.0/24"],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ssh_password_auth_enabled"] is False
    assert body["ssh_allow_root_login"] is True
    assert body["ssh_port"] == 2222
    assert body["ssh_allowed_source_networks"] == ["10.0.0.0/24"]
    assert len(body["ssh_authorized_keys"]) == 1
    # Public keys are NOT secrets — returned verbatim.
    assert body["ssh_authorized_keys"][0]["public_key"] == _ED

    settings = await db_session.get(PlatformSettings, 1)
    assert settings is not None
    assert settings.ssh_port == 2222
    assert settings.ssh_authorized_keys[0]["name"] == "alice"


@pytest.mark.asyncio
async def test_disable_password_auth_no_keys_rejected(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="sshsuper2", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"ssh_password_auth_enabled": False, "ssh_authorized_keys": []},
    )
    assert resp.status_code == 422, resp.text
    assert "lock yourself out" in resp.text.lower() or "lock" in resp.text.lower()


@pytest.mark.asyncio
async def test_disable_password_auth_with_key_ok(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="sshsuper3", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={
            "ssh_password_auth_enabled": False,
            "ssh_authorized_keys": [{"public_key": _ED}],
        },
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_malformed_public_key_rejected(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_user(db_session, username="sshsuper4", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"ssh_authorized_keys": [{"public_key": "this is not a key"}]},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_privileged_port_rejected(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_user(db_session, username="sshsuper5", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    # 80 is < 1024 and not 22 → rejected.
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"ssh_port": 80},
    )
    assert resp.status_code == 422, resp.text
    # 22 is the allowed exception.
    resp_ok = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"ssh_port": 22},
    )
    assert resp_ok.status_code == 200, resp_ok.text


@pytest.mark.asyncio
async def test_ssh_change_wakes_hostconfig(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, token = await _make_user(db_session, username="sshsuper6", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    woke: list[str] = []

    async def _capture(channel: str) -> int:
        woke.append(channel)
        return 0

    monkeypatch.setattr("app.api.v1.settings.router.publish_wake", _capture)
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"ssh_allow_root_login": True},
    )
    assert resp.status_code == 200, resp.text
    from app.core.agent_wake import HOSTCONFIG_ALL

    assert HOSTCONFIG_ALL in woke


@pytest.mark.asyncio
async def test_audit_row_written(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_user(db_session, username="sshsuper7", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={
            "ssh_authorized_keys": [{"name": "bob", "public_key": _ED, "comment": ""}],
            "ssh_port": 2222,
        },
    )
    assert resp.status_code == 200, resp.text
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "platform_settings",
                    AuditLog.resource_id == "ssh",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].action == "update"
    assert rows[0].new_value["port"] == 2222
    assert rows[0].old_value["port"] == 22
    assert rows[0].changed_fields == ["authorized_keys", "port"]
    # Keys are recorded by fingerprint, never in full (#3995).
    key = rows[0].new_value["authorized_keys"][0]
    assert key["fingerprint"].startswith("SHA256:")
    assert _ED.split()[1] not in repr(rows[0].new_value)
    assert "public_key" not in key


@pytest.mark.asyncio
async def test_denied_without_write_settings(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_user(db_session, username="sshviewer", superadmin=False)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"ssh_allow_root_login": True},
    )
    assert resp.status_code == 403, resp.text


# ── #1009 — ssh_lockdown, the switch that makes the allowlist enforcement ──


@pytest.mark.asyncio
async def test_lockdown_defaults_off_and_leaves_the_scope_inert(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The reason nothing tightens on upgrade.

    An operator who configured an allowlist while it was inert (which it was,
    on the default port, from #157 until #1009) must not have their SSH
    restricted by an upgrade they never asked for.
    """
    from app.services.appliance.ssh import effective_ssh_scope

    _, token = await _make_user(db_session, username="sshlock1", superadmin=True)
    await db_session.commit()
    resp = await client.put(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"ssh_allowed_source_networks": ["10.0.0.0/8"]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ssh_lockdown"] is False

    row = await db_session.get(PlatformSettings, 1)
    await db_session.refresh(row)
    assert list(row.ssh_allowed_source_networks) == ["10.0.0.0/8"]
    # ...and the resolved scope, which is what every renderer consumes, is
    # empty — so the port-22 floor stays and the rule stays unscoped.
    assert effective_ssh_scope(row) == []


@pytest.mark.asyncio
async def test_lockdown_with_an_empty_list_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Not a restriction — a closed port, on every appliance at once.

    ``docs/design/FLEET_FIREWALL.md`` §6.1 specified this same 422 for the
    same combination under its ``firewall_mgmt_lockdown`` name.
    """
    _, token = await _make_user(db_session, username="sshlock2", superadmin=True)
    await db_session.commit()
    resp = await client.put(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"ssh_lockdown": True},
    )
    assert resp.status_code == 422, resp.text
    assert "empty allowed-networks list" in resp.text


@pytest.mark.asyncio
async def test_lockdown_from_outside_the_scope_needs_an_acknowledgement(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The mistake an operator actually makes.

    Advisory rather than a refusal — browsing the UI from one network and
    SSHing from another is legitimate — but it must be acknowledged, because
    the alternative is finding out at the next SSH attempt.
    """
    _, token = await _make_user(db_session, username="sshlock3", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}", "X-Real-IP": "203.0.113.9"}

    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"ssh_lockdown": True, "ssh_allowed_source_networks": ["10.0.0.0/8"]},
    )
    assert resp.status_code == 422, resp.text
    assert "not inside the allowed networks" in resp.text

    forced = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={
            "ssh_lockdown": True,
            "ssh_allowed_source_networks": ["10.0.0.0/8"],
            "ssh_lockdown_force": True,
        },
    )
    assert forced.status_code == 200, forced.text
    assert forced.json()["ssh_lockdown"] is True


@pytest.mark.asyncio
async def test_lockdown_from_inside_the_scope_needs_no_acknowledgement(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    from app.services.appliance.ssh import effective_ssh_scope

    _, token = await _make_user(db_session, username="sshlock4", superadmin=True)
    await db_session.commit()
    resp = await client.put(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}", "X-Real-IP": "10.1.2.3"},
        json={"ssh_lockdown": True, "ssh_allowed_source_networks": ["10.0.0.0/8"]},
    )
    assert resp.status_code == 200, resp.text

    row = await db_session.get(PlatformSettings, 1)
    await db_session.refresh(row)
    assert effective_ssh_scope(row) == ["10.0.0.0/8"]


@pytest.mark.asyncio
async def test_the_force_flag_is_never_written_as_a_column(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """It is an acknowledgement, and ``changes`` is both the write set and
    the audit payload — so leaving it in would 500 on setattr and, worse,
    record a field that does not exist."""
    _, token = await _make_user(db_session, username="sshlock5", superadmin=True)
    await db_session.commit()
    resp = await client.put(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}", "X-Real-IP": "10.1.2.3"},
        json={
            "ssh_lockdown": True,
            "ssh_allowed_source_networks": ["10.0.0.0/8"],
            "ssh_lockdown_force": True,
        },
    )
    assert resp.status_code == 200, resp.text
    assert "ssh_lockdown_force" not in resp.json()
    row = await db_session.get(PlatformSettings, 1)
    assert not hasattr(row, "ssh_lockdown_force")


@pytest.mark.asyncio
async def test_turning_lockdown_off_again_is_always_allowed(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The recovery path, and it must never need an acknowledgement.

    An operator who has locked themselves out of SSH still has the Web UI
    (scoped separately, by ``web_ui_allowed_cidrs``), and this is what they
    reach for. Refusing it because their address is outside the scope they
    are trying to REMOVE would be exactly backwards.
    """
    _, token = await _make_user(db_session, username="sshlock6", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}", "X-Real-IP": "203.0.113.9"}
    await client.put(
        "/api/v1/settings",
        headers=headers,
        json={
            "ssh_lockdown": True,
            "ssh_allowed_source_networks": ["10.0.0.0/8"],
            "ssh_lockdown_force": True,
        },
    )
    resp = await client.put("/api/v1/settings", headers=headers, json={"ssh_lockdown": False})
    assert resp.status_code == 200, resp.text
    assert resp.json()["ssh_lockdown"] is False


@pytest.mark.asyncio
async def test_toggling_lockdown_changes_the_bundle_hash() -> None:
    """The hash is the ONLY thing that re-fires the host runner.

    ``_fire_host_config`` short-circuits on an unchanged ``config_hash``, and
    the scope appears in neither of the two bodies the hash used to be built
    from (it is an nftables scope, not an sshd directive). So toggling
    lockdown would change the effective scope and nothing else: no trigger,
    ``50-spatium-ssh.nft`` keeps its UNCONDITIONAL accept — which sorts ahead
    of the scoped management line — while the firewall plane has already
    retired the port-22 floor. SSH open from anywhere, every surface
    reporting it restricted: the #1009 bug, re-created one layer down.
    """
    from app.services.appliance.ssh import ssh_bundle

    off = PlatformSettings(id=1, ssh_allowed_source_networks=["10.0.0.0/8"], ssh_lockdown=False)
    on = PlatformSettings(id=1, ssh_allowed_source_networks=["10.0.0.0/8"], ssh_lockdown=True)
    b_off, b_on = ssh_bundle(off), ssh_bundle(on)

    assert b_off["config_hash"] != b_on["config_hash"]
    # ...and the payload the runner renders from moved with it.
    assert b_off["allowed_source_networks"] == []
    assert b_on["allowed_source_networks"] == ["10.0.0.0/8"]


@pytest.mark.asyncio
async def test_narrowing_the_scope_changes_the_bundle_hash() -> None:
    """Same trap, one step along: editing the CIDRs under an already-on
    lockdown must re-fire, or the host keeps enforcing the OLD scope."""
    from app.services.appliance.ssh import ssh_bundle

    wide = PlatformSettings(id=1, ssh_allowed_source_networks=["10.0.0.0/8"], ssh_lockdown=True)
    narrow = PlatformSettings(id=1, ssh_allowed_source_networks=["10.1.0.0/16"], ssh_lockdown=True)
    assert ssh_bundle(wide)["config_hash"] != ssh_bundle(narrow)["config_hash"]


@pytest.mark.asyncio
async def test_the_hash_is_stable_for_unchanged_settings() -> None:
    """Deterministic, or every heartbeat re-fires the runner forever."""
    from app.services.appliance.ssh import ssh_bundle

    def row() -> PlatformSettings:
        return PlatformSettings(
            id=1,
            ssh_allowed_source_networks=["10.0.0.0/8"],
            ssh_lockdown=True,
            ssh_port=2222,
        )

    assert ssh_bundle(row())["config_hash"] == ssh_bundle(row())["config_hash"]


@pytest.mark.asyncio
async def test_an_unrelated_ssh_save_under_lockdown_needs_no_acknowledgement(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The pre-flight gates on the TRANSITION, not the resulting state.

    Keyed on the latter it fires on every ``ssh_*`` save made while lockdown
    is already on — adding a key, changing the port — demanding an
    acknowledgement for a change that alters nothing about who can reach the
    box. An operator asked to accept a lockout warning for an unrelated edit
    learns to tick it without reading.
    """
    _, token = await _make_user(db_session, username="sshlock7", superadmin=True)
    await db_session.commit()
    outside = {"Authorization": f"Bearer {token}", "X-Real-IP": "203.0.113.9"}

    setup = await client.put(
        "/api/v1/settings",
        headers=outside,
        json={
            "ssh_lockdown": True,
            "ssh_allowed_source_networks": ["10.0.0.0/8"],
            "ssh_lockdown_force": True,
        },
    )
    assert setup.status_code == 200, setup.text

    # An edit that touches neither the flag nor the scope, still from outside.
    resp = await client.put("/api/v1/settings", headers=outside, json={"ssh_port": 2222})
    assert resp.status_code == 200, resp.text
    assert resp.json()["ssh_port"] == 2222
    assert resp.json()["ssh_lockdown"] is True


@pytest.mark.asyncio
async def test_narrowing_the_scope_under_lockdown_does_need_one(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """...but a scope change is a new lockout risk and must be re-checked,
    even though lockdown was already on."""
    _, token = await _make_user(db_session, username="sshlock8", superadmin=True)
    await db_session.commit()
    inside = {"Authorization": f"Bearer {token}", "X-Real-IP": "10.9.9.9"}

    setup = await client.put(
        "/api/v1/settings",
        headers=inside,
        json={"ssh_lockdown": True, "ssh_allowed_source_networks": ["10.0.0.0/8"]},
    )
    assert setup.status_code == 200, setup.text

    # Narrow it to a range that no longer contains the caller.
    resp = await client.put(
        "/api/v1/settings",
        headers=inside,
        json={"ssh_allowed_source_networks": ["10.1.0.0/16"]},
    )
    assert resp.status_code == 422, resp.text
    assert "not inside the allowed networks" in resp.text
