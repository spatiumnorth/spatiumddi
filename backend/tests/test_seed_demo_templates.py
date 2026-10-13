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
