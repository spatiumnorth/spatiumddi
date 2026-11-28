"""Every compiled option 82 test parses in the real ``kea-dhcp4`` (#54).

The expressions come from ``backend/tests/fixtures/relay_match_golden.json``,
which the backend test proves the compiler reproduces. Skipped where
``kea-dhcp4`` is not installed (CI runs it in the built Kea image).

A bad test fails the WHOLE group's config on the agent, so "the compiler's
output parses" is the property that has to be checked against Kea itself, not
against a copy of its grammar.

Behaviour, not just syntax, was measured by hand on kea-dhcp4 3.0.3: with
circuit-id 'eth0/1:100', ``ends_with ':100'`` matched; a value of exactly the
suffix matched; a sub-option shorter than the suffix, or a different suffix,
did not match and Kea carried on serving. ``slice offset 2 0064`` matched
00 04 00 64 01 07 and not 00 04 00 65 01 07, nor a 2- or 3-byte value.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

GOLDEN = Path(__file__).resolve().parents[3] / "backend/tests/fixtures/relay_match_golden.json"

pytestmark = pytest.mark.skipif(shutil.which("kea-dhcp4") is None, reason="kea-dhcp4 not installed")


def _config(test: str) -> dict:
    return {
        "Dhcp4": {
            "interfaces-config": {"interfaces": ["*"]},
            "lease-database": {"type": "memfile", "persist": False},
            "client-classes": [{"name": "relay-match", "test": test}],
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "192.0.2.0/24",
                    "pools": [{"pool": "192.0.2.10-192.0.2.20", "client-classes": ["relay-match"]}],
                }
            ],
        }
    }


@pytest.mark.parametrize("case", json.loads(GOLDEN.read_text()), ids=lambda c: c["expression"][:60])
def test_kea_accepts_the_compiled_test(case: dict, tmp_path: Path) -> None:
    cfg = tmp_path / "kea.json"
    cfg.write_text(json.dumps(_config(case["expression"])))
    res = subprocess.run(
        ["kea-dhcp4", "-t", str(cfg)], capture_output=True, text=True, timeout=30, check=False
    )
    assert res.returncode == 0, res.stdout + res.stderr
