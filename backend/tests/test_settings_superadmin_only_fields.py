"""Which ``PUT /settings`` fields a ``write:settings`` delegate may change.

The Settings page offers every field to superadmins only. On the server, a
delegate holding ``write`` on ``settings`` may change only the fields in
``SETTINGS_DELEGATE_WRITABLE``; every other field is superadmin-only. These
tests walk the whole ``SettingsUpdate`` model so a new field has to be
classified here before the suite passes.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.settings.router import SETTINGS_DELEGATE_WRITABLE, SettingsUpdate
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.settings import PlatformSettings
from app.services import feature_modules as fm_svc

# One valid value per superadmin-only field. A delegate sending any one of
# them alone is refused.
SUPERADMIN_ONLY_VALUES: dict[str, Any] = {
    "app_title": "Other title",
    "app_base_url": "https://ddi.example.test",
    "login_banner_enabled": True,
    "login_banner_title": "Notice",
    "login_banner_text": "Authorised use only",
    "login_banner_require_ack": True,
    "env_banner_enabled": True,
    "env_banner_text": "PROD",
    "env_banner_bg": "#000000",
    "env_banner_fg": "#ffffff",
    "env_banner_position": "bottom",
    "session_timeout_minutes": 45,
    "auto_logout_minutes": 45,
    "github_release_check_enabled": False,
    "reverse_dns_enabled": True,
    "reverse_dns_interval_minutes": 120,
    "reverse_dns_resolvers": ["192.0.2.53"],
    "audit_forward_syslog_enabled": True,
    "audit_forward_syslog_host": "192.0.2.10",
    "audit_forward_syslog_port": 1514,
    "audit_forward_syslog_protocol": "tcp",
    "audit_forward_syslog_facility": 17,
    "audit_forward_webhook_enabled": True,
    "audit_forward_webhook_url": "https://hook.example.test/in",
    "audit_forward_webhook_auth_header": "Bearer abc",
    "dhcp_default_dns_servers": ["192.0.2.53"],
    "dhcp_default_ntp_servers": ["192.0.2.123"],
    "oui_lookup_enabled": True,
    "oui_update_interval_hours": 48,
    "domain_whois_interval_hours": 48,
    "fingerbank_api_key": "fb-key",
    "asn_whois_interval_hours": 48,
    "rpki_roa_source": "ripe",
    "rpki_roa_refresh_interval_hours": 12,
    "bgp_monitoring_enabled": True,
    "bgp_monitoring_interval_hours": 12,
    "ai_daily_digest_enabled": True,
    "password_min_length": 16,
    "password_require_uppercase": True,
    "password_require_lowercase": True,
    "password_require_digit": True,
    "password_require_symbol": True,
    "password_history_count": 3,
    "password_max_age_days": 90,
    "lockout_threshold": 5,
    "lockout_duration_minutes": 20,
    "lockout_reset_minutes": 20,
    "snmp_enabled": True,
    "snmp_version": "v2c",
    "snmp_community": "community",
    "snmp_v3_users": [],
    "snmp_allowed_sources": ["192.0.2.0/24"],
    "snmp_sys_contact": "noc@example.test",
    "snmp_sys_location": "rack 1",
    "ntp_source_mode": "servers",
    "ntp_pool_servers": ["pool.example.test"],
    "ntp_custom_servers": [],
    "ntp_allow_clients": True,
    "ntp_allow_client_networks": ["192.0.2.0/24"],
    "timezone": "UTC",
    "console_mode": "text_console",
    "supervisor_registration_enabled": True,
    "maintenance_mode_enabled": True,
    "maintenance_message": "Change window",
    "lldp_enabled": True,
    "lldp_tx_interval": 60,
    "lldp_tx_hold": 5,
    "lldp_protocols": ["cdp"],
    "lldp_interface_pattern": "eth*",
    "lldp_management_pattern": "eth0",
    "lldp_sys_name": "ddi",
    "lldp_sys_description": "ddi",
    "lldp_med_location": {},
    "lldp_snmp_agentx": True,
    "syslog_enabled": True,
    "syslog_targets": [],
    "syslog_filter": "*.info",
    "syslog_buffer_disk": True,
    "ssh_authorized_keys": [],
    "ssh_password_auth_enabled": False,
    "ssh_allow_root_login": True,
    "ssh_port": 2222,
    "ssh_allowed_source_networks": ["192.0.2.0/24"],
    "ssh_lockdown": False,
    "resolver_mode": "automatic",
    "resolver_servers": ["192.0.2.53"],
    "resolver_fallback_servers": ["192.0.2.54"],
    "resolver_search_domains": ["example.test"],
    "resolver_dnssec": "yes",
    "resolver_dns_over_tls": "opportunistic",
    "apt_managed": True,
    "apt_sources": [],
    "apt_gpg_keys": [],
    "apt_proxy_http": "http://proxy.example.test:3128",
    "apt_proxy_https": "http://proxy.example.test:3128",
    "apt_proxy_no_proxy": "localhost",
    "apt_auth": [],
    "apt_unattended_upgrades_enabled": True,
    "apt_unattended_origins": ["Debian"],
    "apt_unattended_blocklist": ["linux-image-*"],
    "apt_unattended_automatic_reboot": True,
    "apt_unattended_reboot_time": "03:30",
}

# One valid value per delegate-writable field.
DELEGATE_VALUES: dict[str, Any] = {
    "ip_allocation_strategy": "sequential",
    "utilization_warn_threshold": 70,
    "utilization_critical_threshold": 90,
    "utilization_max_prefix_ipv4": 29,
    "utilization_max_prefix_ipv6": 126,
    "subnet_tree_default_expanded_depth": 2,
    "dns_default_ttl": 600,
    "dns_default_zone_type": "primary",
    "dns_default_dnssec_validation": "auto",
    "dns_recursive_by_default": False,
    "dns_auto_sync_enabled": True,
    "dns_auto_sync_interval_minutes": 15,
    "dns_auto_sync_delete_stale": True,
    "dns_pull_from_server_enabled": True,
    "dns_pull_from_server_interval_minutes": 15,
    "dhcp_pull_leases_enabled": True,
    "dhcp_pull_leases_interval_seconds": 60,
    "dhcp_default_lease_time": 7200,
    "dhcp_default_domain_name": "example.test",
    "dhcp_default_domain_search": ["example.test"],
    "vrf_strict_rd_validation": True,
}

# Not plain fields: acknowledgements, and integration switches (a delegate
# is refused only a real flip; tests/test_integration_module_gates.py).
_NOT_FIELDS = {"ssh_lockdown_force", "acknowledge_console_only"}


async def _settings_editor(db: AsyncSession) -> dict[str, str]:
    role = Role(
        name=f"settings-editor-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[{"action": "write", "resource_type": "settings"}],
    )
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    user = User(
        username=f"se-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="settings editor",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=False,
    )
    user.groups = [group]
    db.add_all([role, group, user])
    if await db.get(PlatformSettings, 1) is None:
        db.add(PlatformSettings(id=1))
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="superadmin",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    if await db.get(PlatformSettings, 1) is None:
        db.add(PlatformSettings(id=1))
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _row_snapshot(db: AsyncSession) -> dict[str, Any]:
    db.expire_all()
    row = await db.get(PlatformSettings, 1)
    assert row is not None
    return {c.key: getattr(row, c.key) for c in PlatformSettings.__table__.columns}


def test_every_settings_field_is_classified() -> None:
    fields = set(SettingsUpdate.model_fields)
    integration = set(fm_svc.INTEGRATION_FIELD_TO_MODULE)
    assert set(DELEGATE_VALUES) == set(SETTINGS_DELEGATE_WRITABLE)
    assert not set(SUPERADMIN_ONLY_VALUES) & SETTINGS_DELEGATE_WRITABLE
    unclassified = fields - SETTINGS_DELEGATE_WRITABLE - set(SUPERADMIN_ONLY_VALUES)
    unclassified -= integration | _NOT_FIELDS
    assert not unclassified, f"classify these settings fields: {sorted(unclassified)}"
    assert SETTINGS_DELEGATE_WRITABLE <= fields


@pytest.mark.asyncio
@pytest.mark.parametrize("field", sorted(SUPERADMIN_ONLY_VALUES))
async def test_delegate_is_refused_superadmin_only_field(
    client: AsyncClient, db_session: AsyncSession, field: str
) -> None:
    headers = await _settings_editor(db_session)
    before = await _row_snapshot(db_session)
    r = await client.put(
        "/api/v1/settings", headers=headers, json={field: SUPERADMIN_ONLY_VALUES[field]}
    )
    assert r.status_code == 403, f"{field}: {r.status_code} {r.text}"
    assert "superadmin" in r.json()["detail"].lower()
    assert await _row_snapshot(db_session) == before


@pytest.mark.asyncio
async def test_superadmin_only_field_mixed_with_allowed_one_writes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _settings_editor(db_session)
    before = await _row_snapshot(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"dns_default_ttl": 1234, "app_base_url": "https://ddi.example.test"},
    )
    assert r.status_code == 403, r.text
    assert "app_base_url" in r.json()["detail"]
    assert await _row_snapshot(db_session) == before
    denied = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "platform_settings",
                    AuditLog.result == "denied",
                )
            )
        )
        .scalars()
        .all()
    )
    assert [d.error_detail for d in denied] == ["superadmin_only_settings: app_base_url"]


@pytest.mark.asyncio
@pytest.mark.parametrize("field", sorted(DELEGATE_VALUES))
async def test_delegate_may_write_delegate_field(
    client: AsyncClient, db_session: AsyncSession, field: str
) -> None:
    headers = await _settings_editor(db_session)
    r = await client.put("/api/v1/settings", headers=headers, json={field: DELEGATE_VALUES[field]})
    assert r.status_code == 200, f"{field}: {r.status_code} {r.text}"


@pytest.mark.asyncio
async def test_superadmin_may_set_app_base_url(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    r = await client.put(
        "/api/v1/settings", headers=headers, json={"app_base_url": "https://ddi.example.test"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["app_base_url"] == "https://ddi.example.test"


@pytest.mark.asyncio
async def test_delegate_is_refused_the_resolver_endpoint(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _settings_editor(db_session)
    r = await client.put(
        "/api/v1/settings/resolver", headers=headers, json={"resolver_dnssec": "yes"}
    )
    assert r.status_code == 403, r.text
