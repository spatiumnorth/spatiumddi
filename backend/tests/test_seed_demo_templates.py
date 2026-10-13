"""scripts/seed_demo.py must send IPAM template payloads the API accepts (#1465)."""

import importlib.util
import pathlib

import pytest

from app.api.v1.ipam.templates_router import IPAMTemplateCreate  # noqa: E402

_SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "seed_demo.py"


class _Recorder:
    def __init__(self) -> None:
        self.bodies: list[dict] = []

    def call(self, method, path, **kwargs):
        if path == "/api/v1/ipam/templates":
            self.bodies.append(kwargs["json"])
        return None


def test_seeded_templates_validate_against_the_api_model():
    if not _SCRIPT.is_file():
        pytest.skip("scripts/ not present in this container")
    spec = importlib.util.spec_from_file_location("seed_demo_under_test", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rec = _Recorder()
    mod.seed_ipam_templates(rec, "00000000-0000-0000-0000-000000000001", None)
    assert len(rec.bodies) == 2
    for body in rec.bodies:
        IPAMTemplateCreate(**body)
