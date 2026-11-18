"""scripts/seed_demo.py must send IPAM template payloads the API accepts (#1465)."""

import importlib.util
import pathlib

import httpx
import pytest

from app.api.v1.ipam.templates_router import IPAMTemplateCreate

_SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "seed_demo.py"


def _load_script():
    if not _SCRIPT.is_file():
        pytest.skip("scripts/ not present in this container")
    spec = importlib.util.spec_from_file_location("seed_demo_under_test", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Recorder:
    def __init__(self) -> None:
        self.bodies: list[dict] = []

    def call(self, method, path, **kwargs):
        if path == "/api/v1/ipam/templates":
            self.bodies.append(kwargs["json"])
        return None


def test_seeded_templates_validate_against_the_api_model():
    mod = _load_script()
    rec = _Recorder()
    mod.seed_ipam_templates(rec, "00000000-0000-0000-0000-000000000001", None)
    assert len(rec.bodies) == 2
    for body in rec.bodies:
        IPAMTemplateCreate(**body)


def test_api_records_failed_requests_but_not_conflicts():
    """A refused request is recorded so the run can exit non-zero; a 409
    (already exists) is the re-run path and must not count."""
    mod = _load_script()

    def handler(request: httpx.Request) -> httpx.Response:
        return {
            "/ok": httpx.Response(200, json={"id": "x"}),
            "/exists": httpx.Response(409, json={"detail": "exists"}),
        }.get(request.url.path, httpx.Response(422, json={"detail": "bad"}))

    a = mod.Api("http://seed.test", "token")
    a.c = httpx.Client(base_url="http://seed.test", transport=httpx.MockTransport(handler))
    assert a.call("GET", "/ok") == {"id": "x"}
    assert a.call("POST", "/exists") is None
    assert a.failures == []
    assert a.call("POST", "/refused") is None
    assert a.failures == ["POST /refused -> 422"]


class _SeedRecorder:
    """Stand-in for ``Api`` that serves canned GETs and records writes."""

    def __init__(self, zones=None) -> None:
        self.zones = zones or []
        self.writes: list[tuple[str, str, dict]] = []
        self.failures: list[str] = []

    def call(self, method, path, **kwargs):
        if method == "GET" and path.endswith("/dns/groups"):
            return [{"id": "g1", "name": "default"}]
        if method == "GET" and path.endswith("/zones"):
            return self.zones
        if method == "GET":
            return []
        self.writes.append((method, path, kwargs.get("json", {})))
        return None


def test_seed_dns_finds_fully_qualified_zones_and_sends_valid_records():
    """#3828: zone names come back with a trailing dot; the record block used
    to be skipped silently, and the SRV payload was the old one."""
    from app.api.v1.dns.router import RecordCreate

    mod = _load_script()
    rec = _SeedRecorder(
        zones=[
            {"id": "fz", "name": "corp.example.com."},
            {"id": "rz", "name": "10.in-addr.arpa."},
        ]
    )
    gid, fz_id, rz_id = mod.seed_dns(rec)
    assert (fz_id, rz_id) == ("fz", "rz")
    bodies = [b for _, p, b in rec.writes if p.endswith("/zones/fz/records")]
    assert {b["record_type"] for b in bodies} >= {"A", "MX", "SRV", "TXT"}
    for body in bodies:
        RecordCreate(**body)


def test_seed_dns_missing_zone_is_a_failure_not_a_silent_skip():
    mod = _load_script()
    rec = _SeedRecorder(zones=[])
    mod.seed_dns(rec)
    assert rec.failures


def test_seeded_dhcp_scope_payload_validates():
    from app.api.v1.dhcp.scopes import ScopeCreate

    mod = _load_script()
    rec = _SeedRecorder()
    mod.seed_dhcp_scope(
        rec, "00000000-0000-0000-0000-000000000001", [{"id": "s1", "name": "Servers"}]
    )
    bodies = [b for m, p, b in rec.writes if p.endswith("/dhcp-scopes")]
    assert len(bodies) == 1
    ScopeCreate(**bodies[0])
    assert "ddns_enabled" not in bodies[0]


def test_demo_modules_cover_every_gated_router_the_seeder_posts_to():
    mod = _load_script()
    assert {"network.domains", "ipam.nat"} <= set(mod.DEMO_MODULES)


def test_demo_data_avoids_common_lan_ranges():
    _load_script()
    assert "192.168." not in _SCRIPT.read_text()
