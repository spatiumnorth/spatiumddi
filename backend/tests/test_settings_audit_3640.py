"""#3640 — every settings save leaves an ``audit_log`` row (non-negotiable #4).

Only SSH, resolver, syslog, APT, maintenance, supervisor registration,
branding, retention and the integration switches wrote one; every other field
was saved with a ``logger.info`` line and nothing durable. The guard below
changes EVERY field the PUT accepts and asserts a row records it, so a new
field cannot skip the audit.
"""

from __future__ import annotations

import base64
import json
import typing
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.settings import router as settings_router
from app.api.v1.settings.router import SettingsUpdate
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.services import feature_modules as fm_svc


def _ed25519_key() -> str:
    name = b"ssh-ed25519"
    key = b"\x00" * 32
    blob = len(name).to_bytes(4, "big") + name + len(key).to_bytes(4, "big") + key
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " alice@host"


# Acknowledgements, not columns (popped before anything is written).
NOT_COLUMNS = {"ssh_lockdown_force", "acknowledge_console_only"}

# Fields a plain "different value" generator cannot produce (validators,
# cross-field guards, enumerations). Each maps to a value that differs from the
# default and is accepted on its own.
VALUES: dict[str, Any] = {
    "app_base_url": "https://ddi.example.test",
    "ip_allocation_strategy": "random",
    "dns_default_zone_type": "forward",
    "dns_default_dnssec_validation": "no",
    "reverse_dns_resolvers": ["192.0.2.53"],
    "audit_forward_syslog_protocol": "tcp",
    "audit_forward_syslog_facility": 5,
    "audit_forward_syslog_port": 1514,
    "audit_forward_syslog_host": "syslog.example.test",
    "audit_forward_webhook_url": "https://hooks.example.test/secret-path-3640",
    "audit_forward_webhook_auth_header": "Bearer hunter2-3640",
    "dhcp_default_dns_servers": ["192.0.2.53"],
    "dhcp_default_domain_search": ["example.test"],
    "dhcp_default_ntp_servers": ["192.0.2.123"],
    "fingerbank_api_key": "fb-key-secret-3640",
    "rpki_roa_source": "ripe",
    "snmp_version": "v3",
    "snmp_community": "community-secret-3640",
    "snmp_allowed_sources": ["192.0.2.0/24"],
    "snmp_v3_users": [
        {
            "username": "u3640",
            "auth_protocol": "SHA",
            "auth_pass": "authpass-secret-3640",
            "priv_protocol": "AES",
            "priv_pass": "privpass-secret-3640",
        }
    ],
    "ntp_source_mode": "servers",
    "ntp_pool_servers": ["pool.example.test"],
    "ntp_custom_servers": [{"host": "ntp.example.test", "iburst": True}],
    "ntp_allow_client_networks": ["192.0.2.0/24"],
    "timezone": "Europe/Paris",
    "console_mode": "text_console",
    "lldp_protocols": ["cdp"],
    "lldp_med_location": {"elin": "5551234567"},
    "env_banner_bg": "#112233",
    "env_banner_fg": "#445566",
    "ssh_port": 2222,
    "ssh_allowed_source_networks": ["192.0.2.0/24"],
    "lldp_sys_name": "sysname-3640",
    "syslog_targets": [
        {"host": "logs.example.test", "port": 514, "protocol": "udp", "format": "rfc5424"}
    ],
    "ssh_authorized_keys": [],
    "resolver_mode": "override",
    "resolver_servers": ["192.0.2.53"],
    "resolver_fallback_servers": ["192.0.2.54"],
    "resolver_search_domains": ["example.test"],
    "resolver_dnssec": "yes",
    "resolver_dns_over_tls": "yes",
    "apt_sources": [
        {
            "name": "mirror",
            "uri": "https://mirror.example.test/debian",
            "suites": "stable",
            "components": "main",
            "enabled": True,
        }
    ],
    "apt_gpg_keys": [],
    "apt_auth": [],
    "apt_proxy_http": "http://proxy.example.test:3128",
    "apt_proxy_https": "http://proxy.example.test:3128",
    "apt_unattended_origins": ["origin=Debian"],
    "apt_unattended_blocklist": ["linux-image*"],
    "apt_unattended_reboot_time": "04:30",
    "web_ui_allowed_cidrs": ["192.0.2.0/24"],
}

# Plaintext that must never reach an audit row.
SECRETS = [
    "secret-path-3640",
    "hunter2-3640",
    "fb-key-secret-3640",
    "community-secret-3640",
    "authpass-secret-3640",
    "privpass-secret-3640",
]

# field -> reason, for a field that legitimately writes no platform_settings
# audit row. Empty today: integration switches write a feature_module row.
EXEMPT: dict[str, str] = {}


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
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _other_value(field: str, current: Any) -> Any:
    if field in VALUES:
        return VALUES[field]
    ann = SettingsUpdate.model_fields[field].annotation
    args = [a for a in typing.get_args(ann) if a is not type(None)]
    base = args[0] if args else ann
    if typing.get_origin(base) is typing.Literal:
        return next(v for v in typing.get_args(base) if v != current)
    if base is bool:
        return not current
    if base is int:
        return (current or 0) + 1
    if base is str:
        return f"{current or ''}x"
    raise AssertionError(f"no value generator for {field}: add it to VALUES")


async def _audit_rows(db: AsyncSession) -> list[AuditLog]:
    db.expire_all()
    return list(
        (
            await db.execute(
                select(AuditLog).where(
                    AuditLog.resource_type.in_(["platform_settings", "feature_module"])
                )
            )
        )
        .scalars()
        .all()
    )


FIELDS = sorted(f for f in SettingsUpdate.model_fields if f not in NOT_COLUMNS)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", FIELDS)
async def test_every_settings_field_is_audited(
    client: AsyncClient, db_session: AsyncSession, field: str
) -> None:
    headers = await _superadmin(db_session)
    current = (await client.get("/api/v1/settings", headers=headers)).json().get(field)
    value = _other_value(field, current)
    body: dict[str, Any] = {field: value}
    if field == "resolver_mode":
        body["resolver_servers"] = ["192.0.2.53"]
    if field == "ssh_lockdown":
        body["ssh_allowed_source_networks"] = ["192.0.2.0/24"]
        body["ssh_lockdown_force"] = True
    if field == "ssh_password_auth_enabled":
        body["ssh_authorized_keys"] = [{"name": "k", "public_key": _ed25519_key()}]
    before = {r.id for r in await _audit_rows(db_session)}

    r = await client.put("/api/v1/settings", headers=headers, json=body)
    assert r.status_code == 200, r.text

    new = [r for r in await _audit_rows(db_session) if r.id not in before]
    if field in EXEMPT:
        return
    assert new, f"{field}: saved with no audit_log row"
    blob = json.dumps(
        [[r.resource_id, r.changed_fields, r.old_value, r.new_value] for r in new],
        default=str,
    )
    for secret in SECRETS:
        assert secret not in blob, f"{field}: {secret} leaked into the audit row"
    if field in fm_svc.INTEGRATION_FIELD_TO_MODULE:
        assert any(r.resource_type == "feature_module" for r in new)
    elif not settings_router._is_section_audited(field):
        general = [r for r in new if r.resource_id == "general"]
        assert len(general) == 1, field
        assert field in (general[0].changed_fields or [])
        assert field in (general[0].new_value or {})
        assert field in (general[0].old_value or {})
        assert general[0].action == "update"


@pytest.mark.asyncio
async def test_echoing_the_form_back_writes_no_general_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    r = await client.put("/api/v1/settings", headers=headers, json={"dns_default_ttl": 777})
    assert r.status_code == 200
    r = await client.put("/api/v1/settings", headers=headers, json={"dns_default_ttl": 777})
    assert r.status_code == 200
    rows = [r for r in await _audit_rows(db_session) if r.resource_id == "general"]
    assert len(rows) == 1
    assert rows[0].old_value == {"dns_default_ttl": 3600}
    assert rows[0].new_value == {"dns_default_ttl": 777}


@pytest.mark.asyncio
async def test_secret_rotation_is_recorded_without_the_value(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    for key in ("first-3640", "second-3640"):
        r = await client.put("/api/v1/settings", headers=headers, json={"snmp_community": key})
        assert r.status_code == 200, r.text
    rows = [r for r in await _audit_rows(db_session) if r.resource_id == "general"]
    assert len(rows) == 2
    for row in rows:
        assert row.changed_fields == ["snmp_community"]
        assert "3640" not in json.dumps([row.old_value, row.new_value])
    assert rows[-1].old_value == {"snmp_community": "<set>"} or rows[0].old_value == {
        "snmp_community": "<set>"
    }
