"""TLS certificate monitoring (issue #118).

Covers the probe state-derivation, probe_one's failure-preserves-identity
contract, discovery creation + dedupe, the alert matchers, the router CRUD
+ audit + feature-gate, and the MCP tool registration (name collisions).
The live network probe itself is monkeypatched — these tests never open a
socket.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.feature_module import FeatureModule
from app.models.tls_cert import (
    STATE_EXPIRED,
    STATE_EXPIRING,
    STATE_MISMATCH,
    STATE_OK,
    STATE_UNREACHABLE,
    TLSCertProbe,
    TLSCertTarget,
)
from app.services import feature_modules
from app.services.tls_cert import probe as probe_mod
from app.services.tls_cert.probe import ProbeOutcome, derive_tls_state, probe_one

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_module_cache():
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


async def _superadmin(db: AsyncSession) -> tuple[User, str]:
    u = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ok_outcome(
    *,
    fingerprint: str,
    not_after: datetime,
    chain_valid: bool = True,
    hostname_matches: bool = True,
) -> ProbeOutcome:
    identity = {
        "serial": "deadbeef",
        "subject_cn": "example.com",
        "issuer_cn": "Let's Encrypt",
        "not_before": datetime.now(UTC) - timedelta(days=1),
        "not_after": not_after,
        "sans_json": ["example.com", "www.example.com"],
        "key_algo": "RSA",
        "key_size": 2048,
        "sig_algo": "sha256WithRSAEncryption",
        "chain_depth": 2,
        "chain_valid": chain_valid,
        "chain_error": None if chain_valid else "self signed certificate",
        "self_signed": not chain_valid,
        "fingerprint_sha256": fingerprint,
    }
    return ProbeOutcome(
        ok=True,
        error=None,
        identity=identity,
        hostname_matches=hostname_matches,
        leaf_pem="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
        chain_pem=None,
    )


def _fail_outcome(error: str = "TLS connection failed: refused") -> ProbeOutcome:
    return ProbeOutcome(
        ok=False, error=error, identity=None, hostname_matches=None, leaf_pem=None, chain_pem=None
    )


# ── derive_tls_state (pure unit) ─────────────────────────────────────


def test_derive_tls_state_ordering():
    now = datetime.now(UTC)
    soon = now + timedelta(days=5)
    far = now + timedelta(days=200)
    past = now - timedelta(days=1)

    assert (
        derive_tls_state(ok=False, not_after=far, chain_valid=True, hostname_matches=True, now=now)
        == STATE_UNREACHABLE
    )
    assert (
        derive_tls_state(ok=True, not_after=past, chain_valid=True, hostname_matches=True, now=now)
        == STATE_EXPIRED
    )
    assert (
        derive_tls_state(ok=True, not_after=soon, chain_valid=True, hostname_matches=True, now=now)
        == STATE_EXPIRING
    )
    assert (
        derive_tls_state(ok=True, not_after=far, chain_valid=False, hostname_matches=True, now=now)
        == STATE_MISMATCH
    )
    assert (
        derive_tls_state(ok=True, not_after=far, chain_valid=True, hostname_matches=False, now=now)
        == STATE_MISMATCH
    )
    assert (
        derive_tls_state(ok=True, not_after=far, chain_valid=True, hostname_matches=True, now=now)
        == STATE_OK
    )


# ── probe_one ────────────────────────────────────────────────────────


async def test_probe_one_success_sets_identity(db_session: AsyncSession, monkeypatch):
    t = TLSCertTarget(host="example.com", port=443, display_name="example")
    db_session.add(t)
    await db_session.flush()

    na = datetime.now(UTC) + timedelta(days=200)
    monkeypatch.setattr(
        probe_mod, "fetch_endpoint", lambda *a, **k: _ok_outcome(fingerprint="AA:BB", not_after=na)
    )
    result = await probe_one(db_session, t, default_interval_hours=6)
    await db_session.flush()

    assert result.ok is True
    assert t.state == STATE_OK
    assert t.fingerprint_sha256 == "AA:BB"
    assert t.subject_cn == "example.com"
    assert t.chain_valid is True
    assert t.consecutive_failures == 0
    assert t.next_check_at is not None
    probes = (
        (await db_session.execute(select(TLSCertProbe).where(TLSCertProbe.target_id == t.id)))
        .scalars()
        .all()
    )
    assert len(probes) == 1 and probes[0].ok is True


async def test_probe_one_failure_preserves_identity(db_session: AsyncSession, monkeypatch):
    t = TLSCertTarget(host="example.com", port=443)
    db_session.add(t)
    await db_session.flush()

    na = datetime.now(UTC) + timedelta(days=200)
    monkeypatch.setattr(
        probe_mod, "fetch_endpoint", lambda *a, **k: _ok_outcome(fingerprint="AA:BB", not_after=na)
    )
    await probe_one(db_session, t, default_interval_hours=6)
    await db_session.flush()
    assert t.fingerprint_sha256 == "AA:BB"

    # Now the endpoint goes dark — identity must be preserved, only state flips.
    monkeypatch.setattr(probe_mod, "fetch_endpoint", lambda *a, **k: _fail_outcome())
    result = await probe_one(db_session, t, default_interval_hours=6)
    await db_session.flush()

    assert result.ok is False
    assert t.state == STATE_UNREACHABLE
    assert t.fingerprint_sha256 == "AA:BB"  # PRESERVED
    assert t.subject_cn == "example.com"  # PRESERVED
    assert t.consecutive_failures == 1
    assert t.last_error is not None
    assert result.fingerprint_changed is False  # no spurious "changed"


async def test_probe_one_detects_fingerprint_change(db_session: AsyncSession, monkeypatch):
    t = TLSCertTarget(host="example.com", port=443)
    db_session.add(t)
    await db_session.flush()
    na = datetime.now(UTC) + timedelta(days=200)
    monkeypatch.setattr(
        probe_mod, "fetch_endpoint", lambda *a, **k: _ok_outcome(fingerprint="OLD", not_after=na)
    )
    await probe_one(db_session, t, default_interval_hours=6)
    await db_session.flush()
    monkeypatch.setattr(
        probe_mod, "fetch_endpoint", lambda *a, **k: _ok_outcome(fingerprint="NEW", not_after=na)
    )
    result = await probe_one(db_session, t, default_interval_hours=6)
    assert result.fingerprint_changed is True


# ── discovery ────────────────────────────────────────────────────────


async def test_discovery_creates_and_dedupes(db_session: AsyncSession):
    from app.services.tls_cert.discovery import reconcile_discovered_targets

    group = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:8]}")
    db_session.add(group)
    await db_session.flush()
    zone = DNSZone(group_id=group.id, name="example.com", auto_tls_probe=True)
    db_session.add(zone)
    await db_session.flush()
    for label, fqdn in (("www", "www.example.com"), ("api", "api.example.com")):
        db_session.add(
            DNSRecord(zone_id=zone.id, name=label, fqdn=fqdn, record_type="A", value="203.0.113.10")
        )
    # A second record for the SAME fqdn must dedupe to one target.
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="www",
            fqdn="www.example.com",
            record_type="A",
            value="203.0.113.11",
        )
    )
    await db_session.flush()

    res = await reconcile_discovered_targets(db_session)
    await db_session.flush()
    assert res["created"] == 2  # www + api, deduped

    targets = (await db_session.execute(select(TLSCertTarget))).scalars().all()
    hosts = sorted(t.host for t in targets)
    assert hosts == ["api.example.com", "www.example.com"]
    assert all(t.source == "discovered" and t.dns_zone_id == zone.id for t in targets)

    # Idempotent — a second run creates nothing new.
    res2 = await reconcile_discovered_targets(db_session)
    assert res2["created"] == 0


async def test_discovery_disable_then_reenable_cycle(db_session: AsyncSession):
    from app.services.tls_cert.discovery import reconcile_discovered_targets

    group = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:8]}")
    db_session.add(group)
    await db_session.flush()
    zone = DNSZone(group_id=group.id, name="example.com", auto_tls_probe=True)
    db_session.add(zone)
    await db_session.flush()
    rec = DNSRecord(
        zone_id=zone.id, name="www", fqdn="www.example.com", record_type="A", value="203.0.113.10"
    )
    db_session.add(rec)
    await db_session.flush()

    await reconcile_discovered_targets(db_session)
    await db_session.flush()
    t = (await db_session.execute(select(TLSCertTarget))).scalars().one()
    assert t.enabled is True

    # Opt out → target disabled (key no longer a candidate).
    zone.auto_tls_probe = False
    await db_session.flush()
    res = await reconcile_discovered_targets(db_session)
    await db_session.flush()
    await db_session.refresh(t)
    assert t.enabled is False and res["disabled"] == 1

    # Opt back in → SAME target re-enabled (not a duplicate).
    zone.auto_tls_probe = True
    await db_session.flush()
    res2 = await reconcile_discovered_targets(db_session)
    await db_session.flush()
    await db_session.refresh(t)
    assert t.enabled is True
    assert res2["created"] == 0  # re-enabled, not re-created
    assert (await db_session.execute(select(TLSCertTarget))).scalars().all().__len__() == 1


async def test_discovery_from_ip_role(db_session: AsyncSession):
    """#118 Phase 2 — an IP in a TLS-serving role auto-becomes a target."""
    from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
    from app.services.tls_cert.discovery import reconcile_discovered_targets

    sp = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(sp)
    await db_session.flush()
    blk = IPBlock(space_id=sp.id, network="10.9.0.0/16")
    db_session.add(blk)
    await db_session.flush()
    sn = Subnet(space_id=sp.id, block_id=blk.id, network="10.9.1.0/24")
    db_session.add(sn)
    await db_session.flush()
    ip = IPAddress(
        subnet_id=sn.id,
        address="10.9.1.10",
        role="web",
        # #3297 — ``fqdn`` names the host only while ``hostname`` is set.
        hostname="svc",
        fqdn="svc.example.com",
        status="allocated",
    )
    db_session.add(ip)
    await db_session.flush()

    res = await reconcile_discovered_targets(db_session)
    await db_session.flush()
    assert res["created"] == 1
    t = (await db_session.execute(select(TLSCertTarget))).scalars().one()
    assert t.host == "svc.example.com"
    assert t.ip_address_id == ip.id
    assert t.source == "discovered"

    # Role cleared → target disabled (no longer a TLS-serving IP).
    ip.role = "host"
    await db_session.flush()
    res2 = await reconcile_discovered_targets(db_session)
    await db_session.flush()
    await db_session.refresh(t)
    assert t.enabled is False and res2["disabled"] == 1


async def test_ct_log_no_host():
    from app.services.tls_cert.ct_log import lookup_ct

    out = await lookup_ct("")
    assert out["entries"] == [] and out["count"] == 0 and out["error"]


async def test_issuer_change_alert(db_session: AsyncSession):
    from app.models.alerts import AlertEvent, AlertRule
    from app.services.alerts import (
        RULE_TYPE_TLS_CERT_ISSUER_CHANGED,
        _evaluate_tls_cert_transition_rule,
    )

    now = datetime.now(UTC)
    t = TLSCertTarget(host="rot.example.com", port=443, enabled=True, issuer_cn="Let's Encrypt")
    db_session.add(t)
    rule = AlertRule(name="ic", rule_type=RULE_TYPE_TLS_CERT_ISSUER_CHANGED, severity="warning")
    db_session.add(rule)
    await db_session.flush()

    # First sighting → silent baseline (no open event).
    opened, *_ = await _evaluate_tls_cert_transition_rule(
        db_session, rule, now, value_attr="issuer_cn", what="issuer"
    )
    await db_session.flush()
    assert opened == 0

    # Issuer flips → one open event.
    t.issuer_cn = "Rogue CA"
    await db_session.flush()
    opened2, *_ = await _evaluate_tls_cert_transition_rule(
        db_session, rule, now + timedelta(minutes=1), value_attr="issuer_cn", what="issuer"
    )
    await db_session.flush()
    assert opened2 == 1
    events = (
        (
            await db_session.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id, AlertEvent.resolved_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1 and "Rogue CA" in events[0].message


# ── alert matchers ───────────────────────────────────────────────────


async def test_alert_matchers(db_session: AsyncSession):
    from app.models.alerts import AlertRule
    from app.services.alerts import (
        RULE_TYPE_TLS_CERT_CHAIN_INVALID,
        RULE_TYPE_TLS_CERT_EXPIRING,
        RULE_TYPE_TLS_CERT_UNREACHABLE,
        _matching_tls_cert_chain_invalid_subjects,
        _matching_tls_cert_expiring_subjects,
        _matching_tls_cert_unreachable_subjects,
    )

    now = datetime.now(UTC)
    expiring = TLSCertTarget(
        host="exp.example.com", port=443, enabled=True, not_after=now + timedelta(days=5)
    )
    # Untrusted chain → chain_valid False, state mismatch.
    invalid = TLSCertTarget(
        host="bad.example.com",
        port=443,
        enabled=True,
        chain_valid=False,
        chain_error="self signed",
        state=STATE_MISMATCH,
    )
    # Trusted chain served on the wrong hostname → chain_valid True but
    # state mismatch. Must ALSO fire chain_invalid (the SAN-drift case).
    name_mismatch = TLSCertTarget(
        host="wrongname.example.com",
        port=443,
        enabled=True,
        chain_valid=True,
        state=STATE_MISMATCH,
        not_after=now + timedelta(days=300),
    )
    down = TLSCertTarget(
        host="down.example.com",
        port=443,
        enabled=True,
        state=STATE_UNREACHABLE,
        consecutive_failures=3,
    )
    healthy = TLSCertTarget(
        host="ok.example.com",
        port=443,
        enabled=True,
        state="ok",
        not_after=now + timedelta(days=300),
    )
    db_session.add_all([expiring, invalid, name_mismatch, down, healthy])
    await db_session.flush()

    exp_rule = AlertRule(
        name="x", rule_type=RULE_TYPE_TLS_CERT_EXPIRING, severity="warning", threshold_days=30
    )
    inv_rule = AlertRule(name="y", rule_type=RULE_TYPE_TLS_CERT_CHAIN_INVALID, severity="critical")
    down_rule = AlertRule(name="z", rule_type=RULE_TYPE_TLS_CERT_UNREACHABLE, severity="warning")

    exp_matches = await _matching_tls_cert_expiring_subjects(db_session, exp_rule, now)
    assert {m[0] for m in exp_matches} == {str(expiring.id)}

    # chain_invalid fires for BOTH the untrusted chain AND the trusted-but-
    # wrong-hostname cert (both state='mismatch') — the SAN-drift coverage.
    inv_matches = await _matching_tls_cert_chain_invalid_subjects(db_session, inv_rule)
    assert {m[0] for m in inv_matches} == {str(invalid.id), str(name_mismatch.id)}

    down_matches = await _matching_tls_cert_unreachable_subjects(db_session, down_rule)
    assert {m[0] for m in down_matches} == {str(down.id)}


def _self_signed_pem(cn: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_parse_chain_pem_roles():
    from app.services.tls_cert.probe import parse_chain_pem

    assert parse_chain_pem(None) == []
    assert parse_chain_pem("not a pem") == []

    # leaf (position 0) + a self-signed cert above it → root.
    pem = _self_signed_pem("leaf.example.com") + _self_signed_pem("Example Root CA")
    parsed = parse_chain_pem(pem)
    assert [c["role"] for c in parsed] == ["leaf", "root"]
    assert parsed[0]["subject_cn"] == "leaf.example.com"
    assert parsed[1]["subject_cn"] == "Example Root CA"
    assert parsed[1]["self_signed"] is True
    assert all(c["fingerprint_sha256"] and c["key_algo"] == "EC" for c in parsed)


# ── router CRUD + audit + feature gate ───────────────────────────────


async def test_router_crud_roundtrip(client: AsyncClient, db_session: AsyncSession, monkeypatch):
    _, token = await _superadmin(db_session)
    await db_session.commit()
    h = _hdr(token)

    # Create.
    r = await client.post(
        "/api/v1/tls-certs",
        headers=h,
        json={"host": "Example.COM", "port": 443, "display_name": "Example"},
    )
    assert r.status_code == 201, r.text
    row = r.json()
    assert row["host"] == "example.com"  # normalised lower
    tid = row["id"]

    # Duplicate connect tuple → 409.
    r = await client.post("/api/v1/tls-certs", headers=h, json={"host": "example.com"})
    assert r.status_code == 409, r.text

    # SSRF — loopback literal rejected at validation (422).
    r = await client.post("/api/v1/tls-certs", headers=h, json={"host": "127.0.0.1"})
    assert r.status_code == 422, r.text

    # List + get.
    r = await client.get("/api/v1/tls-certs", headers=h)
    assert r.status_code == 200 and r.json()["total"] >= 1
    r = await client.get(f"/api/v1/tls-certs/{tid}", headers=h)
    assert r.status_code == 200

    # Update.
    r = await client.put(f"/api/v1/tls-certs/{tid}", headers=h, json={"display_name": "Renamed"})
    assert r.status_code == 200 and r.json()["display_name"] == "Renamed"

    # Probe-now (monkeypatched endpoint).
    na = datetime.now(UTC) + timedelta(days=100)
    monkeypatch.setattr(
        probe_mod, "fetch_endpoint", lambda *a, **k: _ok_outcome(fingerprint="ZZ", not_after=na)
    )
    r = await client.post(f"/api/v1/tls-certs/{tid}/probe", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == STATE_OK
    assert r.json()["fingerprint_sha256"] == "ZZ"

    # Delete.
    r = await client.delete(f"/api/v1/tls-certs/{tid}", headers=h)
    assert r.status_code == 204
    r = await client.get(f"/api/v1/tls-certs/{tid}", headers=h)
    assert r.status_code == 404


async def test_router_feature_gate_404(client: AsyncClient, db_session: AsyncSession):
    _, token = await _superadmin(db_session)
    # Disable the module.
    fm = await db_session.get(FeatureModule, "security.tls_certs")
    if fm is None:
        db_session.add(FeatureModule(id="security.tls_certs", enabled=False))
    else:
        fm.enabled = False
    await db_session.commit()
    feature_modules.invalidate_cache()

    r = await client.get("/api/v1/tls-certs", headers=_hdr(token))
    assert r.status_code == 404, r.text


# ── MCP tools ────────────────────────────────────────────────────────


def test_mcp_tool_names_registered_no_collision():
    import app.services.ai.tools  # noqa: F401 — triggers registration
    from app.services.ai.tools.base import REGISTRY

    for name in (
        "find_tls_cert",
        "count_tls_certs_expiring",
        "get_cert_chain",
        "count_tls_targets_by_state",
        "propose_run_cert_probe",
    ):
        assert REGISTRY.get(name) is not None, f"{name} not registered"
    # Distinct from the ACME-client tools (no collision).
    assert REGISTRY.get("find_certificates") is not None
    assert REGISTRY.get("find_tls_cert") is not REGISTRY.get("find_certificates")
