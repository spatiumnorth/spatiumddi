"""#3995 — SSH / resolver / syslog / APT audit rows name only changed fields
with old and new values, write no row for a no-op save, and never record a
secret (keys by fingerprint, GPG / mirror auth / syslog CA by digest)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from tests.test_settings_audit_3640 import _superadmin
from tests.test_settings_ssh import _ED

PEM = "-----BEGIN CERTIFICATE-----\nMIIBsecretCAbody3995\n-----END CERTIFICATE-----\n"
ARMOUR = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\nSECRETKEYBODY3995\n-----END PGP PUBLIC KEY BLOCK-----"
)
SECRETS = [_ED.split()[1], "MIIBsecretCAbody3995", "SECRETKEYBODY3995", "mirrorpw3995"]


async def _rows(db: AsyncSession, rid: str) -> list[AuditLog]:
    db.expire_all()
    res = await db.execute(
        select(AuditLog).where(
            AuditLog.resource_type == "platform_settings", AuditLog.resource_id == rid
        )
    )
    return list(res.scalars().all())


def _blob(rows: list[AuditLog]) -> str:
    return json.dumps([[r.changed_fields, r.old_value, r.new_value] for r in rows], default=str)


async def _put(client: AsyncClient, headers: dict[str, str], body: dict[str, Any]) -> None:
    r = await client.put("/api/v1/settings", headers=headers, json=body)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_resolver_row_names_only_changed_fields(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    await _put(client, h, {"resolver_mode": "override", "resolver_servers": ["1.1.1.1"]})
    before = len(await _rows(db_session, "resolver"))
    await _put(client, h, {"resolver_servers": ["9.9.9.9"], "resolver_mode": "override"})
    rows = await _rows(db_session, "resolver")
    assert len(rows) == before + 1
    last = max(rows, key=lambda r: r.timestamp)
    assert last.changed_fields == ["servers"]
    assert last.old_value == {"servers": ["1.1.1.1"]}
    assert last.new_value == {"servers": ["9.9.9.9"]}


@pytest.mark.asyncio
async def test_noop_saves_write_no_row(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _superadmin(db_session)
    body = {
        "resolver_mode": "override",
        "resolver_servers": ["1.1.1.1"],
        "ssh_authorized_keys": [{"name": "k", "public_key": _ED}],
        "syslog_enabled": True,
        "syslog_targets": [
            {"host": "siem.example", "port": 6514, "protocol": "tls", "ca_cert_pem": PEM}
        ],
        "apt_managed": True,
        "apt_gpg_keys": [{"key_id": "k1", "armoured_text": ARMOUR}],
        "apt_auth": [{"machine": "m.lan", "login": "bob", "password": "mirrorpw3995"}],
    }
    await _put(client, h, body)
    counts = {r: len(await _rows(db_session, r)) for r in ("ssh", "resolver", "syslog", "apt")}
    # Echo the same values back (secrets omitted so the stored ones are kept).
    echo = {
        "resolver_mode": "override",
        "resolver_servers": ["1.1.1.1"],
        "ssh_authorized_keys": [{"name": "k", "public_key": _ED}],
        "syslog_enabled": True,
        "apt_managed": True,
    }
    await _put(client, h, echo)
    for rid, n in counts.items():
        assert len(await _rows(db_session, rid)) == n, rid


@pytest.mark.asyncio
async def test_secrets_never_recorded(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _superadmin(db_session)
    await _put(
        client,
        h,
        {
            "ssh_authorized_keys": [{"name": "k", "public_key": _ED}],
            "syslog_enabled": True,
            "syslog_targets": [
                {"host": "siem.example", "port": 6514, "protocol": "tls", "ca_cert_pem": PEM}
            ],
            "apt_managed": True,
            "apt_gpg_keys": [{"key_id": "k1", "armoured_text": ARMOUR}],
            "apt_auth": [{"machine": "m.lan", "login": "bob", "password": "mirrorpw3995"}],
        },
    )
    for rid in ("ssh", "syslog", "apt"):
        rows = await _rows(db_session, rid)
        assert rows, rid
        blob = _blob(rows)
        for secret in SECRETS:
            assert secret not in blob, f"{rid}: {secret} leaked"
        assert rows[0].changed_fields and rows[0].old_value is not None
    ssh = (await _rows(db_session, "ssh"))[0]
    assert ssh.new_value["authorized_keys"][0]["fingerprint"].startswith("SHA256:")
    sysl = (await _rows(db_session, "syslog"))[0]
    assert sysl.new_value["targets"][0]["ca_fingerprint"]
