"""Supervisor heartbeat delivers host-config blocks (issue #346).

The keystone for the appliance host-config plane: the supervisor heartbeat
response must carry the rendered snmp / chrony / lldp blocks so the
supervisor can fire the host-side reload triggers. Before #346 the response
omitted them entirely (SNMP #153 / NTP #154 / LLDP #343 rendered config that
never reached the supervisor).
"""

from __future__ import annotations

import hashlib
import os
import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token


async def _settings(db: AsyncSession) -> PlatformSettings:
    s = await db.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db.add(s)
    # Only /supervisor/register needs the flag since #2798; kept on for parity.
    s.supervisor_registration_enabled = True
    s.lldp_enabled = True
    s.lldp_tx_interval = 30
    s.lldp_tx_hold = 4
    s.lldp_protocols = ["cdp"]
    s.snmp_enabled = False
    await db.flush()
    return s


async def _approved_supervisor(db: AsyncSession) -> tuple[Appliance, str]:
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="agent-1",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
    )
    db.add(row)
    await db.flush()
    return row, token


async def test_heartbeat_delivers_host_config_blocks(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _settings(db_session)
    row, token = await _approved_supervisor(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token},
    )
    assert r.status_code == 200, r.text
    body = r.json()

    # All three host-config blocks are present with their stable key set.
    assert "snmp_settings" in body and "ntp_settings" in body and "lldp_settings" in body
    lldp = body["lldp_settings"]
    assert lldp["enabled"] is True
    assert lldp["config_hash"]  # non-empty when enabled
    assert "configure lldp tx-interval 30" in lldp["lldpd_conf"]
    assert lldp["daemon_args"] == "-c"  # cdp reception
    # SNMP is off → disabled-shape block (still present, empty hash).
    assert body["snmp_settings"]["enabled"] is False
    assert body["snmp_settings"]["config_hash"] == ""
    # NTP block carries its stable keys too.
    assert "config_hash" in body["ntp_settings"]
    # Issue #156 — syslog block present with its stable key set; off → empty.
    assert "syslog_settings" in body
    assert body["syslog_settings"]["enabled"] is False
    assert body["syslog_settings"]["config_hash"] == ""
    assert body["syslog_settings"]["ca_certs"] == {}
    # Issue #157 — ssh block present with its stable key set; pristine
    # default → disabled (managed-off), empty hash, password auth on.
    assert "ssh_settings" in body
    assert body["ssh_settings"]["enabled"] is False
    assert body["ssh_settings"]["config_hash"] == ""
    assert body["ssh_settings"]["password_auth"] is True
    assert body["ssh_settings"]["key_count"] == 0
    # Issue #158 — resolver block present with its stable key set; default
    # automatic mode → disabled, empty hash, empty body.
    assert "resolver_settings" in body
    assert body["resolver_settings"]["enabled"] is False
    assert body["resolver_settings"]["config_hash"] == ""
    assert body["resolver_settings"]["resolved_conf"] == ""


# ── Issue #156 — syslog bundle + delivery ─────────────────────────────


async def test_syslog_bundle_disabled_and_enabled_shapes() -> None:
    """syslog_bundle returns a STABLE dict shape disabled (empty body /
    hash) and a rendered body + hash when enabled."""
    from app.services.appliance.syslog import syslog_bundle

    off = PlatformSettings(id=1, syslog_enabled=False, syslog_targets=[])
    block = syslog_bundle(off)
    assert block == {
        "enabled": False,
        "config_hash": "",
        "rsyslog_conf": "",
        "ca_certs": {},
    }

    on = PlatformSettings(
        id=1,
        syslog_enabled=True,
        syslog_targets=[
            {"host": "collector.example", "port": 514, "protocol": "udp", "format": "rfc5424"}
        ],
        syslog_filter="*.*",
        syslog_buffer_disk=False,
    )
    block = syslog_bundle(on)
    assert block["enabled"] is True
    assert block["config_hash"]  # non-empty when enabled
    assert 'target="collector.example"' in block["rsyslog_conf"]
    # journald is forwarded — imjournal input block must be present.
    assert 'module(load="imjournal"' in block["rsyslog_conf"]
    assert block["ca_certs"] == {}


async def test_heartbeat_delivers_syslog_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    s = await _settings(db_session)
    s.syslog_enabled = True
    s.syslog_targets = [
        {"host": "siem.example", "port": 6514, "protocol": "tcp", "format": "rfc5424"}
    ]
    s.syslog_filter = "*.*"
    row, token = await _approved_supervisor(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token},
    )
    assert r.status_code == 200, r.text
    block = r.json()["syslog_settings"]
    assert block["enabled"] is True
    assert block["config_hash"]
    assert 'target="siem.example"' in block["rsyslog_conf"]


async def test_syslog_targets_fold_into_dhcp_config_etag(db_session: AsyncSession) -> None:
    """Changing syslog_targets flips the DHCP /config ETag's syslog
    marker — the bundle helper is the same one the agent endpoint mixes
    into the fleet_marker, so the rendered config_hash must move."""
    from app.services.appliance.syslog import syslog_bundle

    s = PlatformSettings(
        id=1,
        syslog_enabled=True,
        syslog_targets=[{"host": "a.example", "port": 514, "protocol": "udp", "format": "rfc5424"}],
        syslog_filter="*.*",
    )
    hash_before = syslog_bundle(s)["config_hash"]
    s.syslog_targets = [{"host": "b.example", "port": 514, "protocol": "udp", "format": "rfc5424"}]
    hash_after = syslog_bundle(s)["config_hash"]
    assert hash_before != hash_after


async def test_ca_rotation_changes_config_hash() -> None:
    """Rotating a TLS target's CA PEM (same host/port/protocol/format,
    new PEM) MUST shift config_hash so the supervisor trigger fires —
    the CA is referenced by a deterministic path so the rendered body is
    byte-identical, and only folding the PEM bytes into the hash makes
    the rotation observable (#156 review FIX 1)."""
    from app.core.crypto import encrypt_str
    from app.services.appliance.syslog import syslog_bundle

    pem_old = "-----BEGIN CERTIFICATE-----\nOLDOLDOLD\n-----END CERTIFICATE-----\n"
    pem_new = "-----BEGIN CERTIFICATE-----\nNEWNEWNEW\n-----END CERTIFICATE-----\n"

    def _settings_with(pem: str) -> PlatformSettings:
        return PlatformSettings(
            id=1,
            syslog_enabled=True,
            syslog_targets=[
                {
                    "host": "siem.example",
                    "port": 6514,
                    "protocol": "tls",
                    "format": "rfc5424",
                    "ca_cert_pem": encrypt_str(pem).decode("ascii"),
                }
            ],
            syslog_filter="*.*",
        )

    before = syslog_bundle(_settings_with(pem_old))
    after = syslog_bundle(_settings_with(pem_new))

    # The rendered body is identical (CA referenced by path), but the
    # hash must differ because the staged CA PEM changed.
    assert before["rsyslog_conf"] == after["rsyslog_conf"]
    assert before["config_hash"] != after["config_hash"]
    # The decrypted PEM is what actually got staged for the host runner.
    assert list(after["ca_certs"].values()) == [pem_new]


async def test_render_drops_target_with_injection_host() -> None:
    """Belt-and-suspenders: even if a malformed JSONB row carries a host
    with an embedded quote (which both write paths now reject), the
    renderer must NOT emit it as a ``target="..."`` action — it drops it
    with an inline comment instead (#156 review FIX 2)."""
    from app.services.appliance.syslog import render_rsyslog_conf

    s = PlatformSettings(
        id=1,
        syslog_enabled=True,
        syslog_targets=[
            {"host": 'a"b', "port": 514, "protocol": "udp", "format": "rfc5424"},
            {"host": "good.example", "port": 514, "protocol": "udp", "format": "rfc5424"},
        ],
        syslog_filter="*.*",
    )
    body = render_rsyslog_conf(s)
    # The bad host never reaches a target= action line — the only place
    # it may appear is the inline "dropped" comment (host repr).
    assert 'target="a"b"' not in body
    assert not any(line.lstrip().startswith('target="a"b"') for line in body.splitlines())
    assert "dropped" in body
    # The good host still renders as a real action.
    assert 'target="good.example"' in body


# ── Issue #157 — ssh bundle + delivery ────────────────────────────────


def _ed25519_key(comment: str = "op@host") -> str:
    import base64 as _b64

    name = b"ssh-ed25519"
    key = b"\x00" * 32
    blob = len(name).to_bytes(4, "big") + name + len(key).to_bytes(4, "big") + key
    return "ssh-ed25519 " + _b64.b64encode(blob).decode("ascii") + " " + comment


async def test_heartbeat_delivers_ssh_block(client: AsyncClient, db_session: AsyncSession) -> None:
    s = await _settings(db_session)
    s.ssh_authorized_keys = [{"name": "op", "public_key": _ed25519_key(), "comment": ""}]
    s.ssh_port = 2222
    row, token = await _approved_supervisor(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token},
    )
    assert r.status_code == 200, r.text
    block = r.json()["ssh_settings"]
    assert block["enabled"] is True
    assert block["config_hash"]
    assert block["ssh_port"] == 2222
    assert block["key_count"] == 1
    assert "Port 2222" in block["sshd_conf"]


async def test_ssh_keys_fold_into_dhcp_config_etag(db_session: AsyncSession) -> None:
    """Changing ssh_authorized_keys flips the DHCP /config ETag's ssh
    marker — the bundle helper is the same one the agent endpoint mixes
    into the fleet_marker, so the rendered config_hash must move."""
    from app.services.appliance.ssh import ssh_bundle

    s = PlatformSettings(
        id=1,
        ssh_authorized_keys=[{"name": "a", "public_key": _ed25519_key(), "comment": ""}],
    )
    hash_before = ssh_bundle(s)["config_hash"]
    # Add a second key — the rendered authorized_keys body changes.
    s.ssh_authorized_keys = [
        {"name": "a", "public_key": _ed25519_key(), "comment": ""},
        {"name": "b", "public_key": _ed25519_key("two@host"), "comment": ""},
    ]
    hash_after = ssh_bundle(s)["config_hash"]
    assert hash_before != hash_after


# ── Issue #158 — resolver bundle + delivery ───────────────────────────


async def test_heartbeat_delivers_resolver_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    s = await _settings(db_session)
    s.resolver_mode = "override"
    s.resolver_servers = ["1.1.1.1", "9.9.9.9"]
    s.resolver_search_domains = ["corp.example.com"]
    row, token = await _approved_supervisor(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token},
    )
    assert r.status_code == 200, r.text
    block = r.json()["resolver_settings"]
    assert block["enabled"] is True
    assert block["config_hash"]
    assert "DNS=1.1.1.1 9.9.9.9" in block["resolved_conf"]
    assert "Domains=~. corp.example.com" in block["resolved_conf"]
    # Never the stub listener.
    assert "DNSStubListener" not in block["resolved_conf"]


async def test_resolver_servers_fold_into_dhcp_config_etag(db_session: AsyncSession) -> None:
    """Changing resolver_servers flips the DHCP /config ETag's resolver
    marker — the bundle helper is the same one the agent endpoint mixes
    into the fleet_marker, so the rendered config_hash must move."""
    from app.services.appliance.resolver import resolver_bundle

    s = PlatformSettings(id=1, resolver_mode="override", resolver_servers=["1.1.1.1"])
    hash_before = resolver_bundle(s)["config_hash"]
    s.resolver_servers = ["9.9.9.9"]
    hash_after = resolver_bundle(s)["config_hash"]
    assert hash_before != hash_after
