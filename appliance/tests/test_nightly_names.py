"""Nightly naming for main vs a release branch (#3950).

``.github/scripts/nightly-names.sh`` is what nightly.yml's gate runs to name a
build. The properties that matter: ``main`` keeps every historical name, a
``release/X.Y.Z`` build gets suffixed ones, the two prune rings are disjoint
(so neither nightly's prune can delete the other's), and the version string
stays an unknown version to ``app/core/versions.py``.

    python3 -m pytest appliance/tests/test_nightly_names.py -v
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / ".github" / "scripts" / "nightly-names.sh"
SHA = "0123456789abcdef0123456789abcdef01234567"


def names(ref: str, night: str = "20261112") -> dict[str, str]:
    out = subprocess.run(
        ["bash", str(SCRIPT), ref, night, SHA], capture_output=True, text=True, check=True
    ).stdout
    return dict(line.split("=", 1) for line in out.splitlines())


def test_main_keeps_the_historical_names() -> None:
    n = names("main")
    assert n["date_tag"] == "nightly-20261112"
    assert n["pointer_tag"] == "nightly"
    assert n["release_tag"] == "nightly-2026.11.12"
    assert n["version"] == "0.0.0-nightly-20261112+0123456"
    assert n["cache_scope"] == "nightly"


def test_release_branch_names_are_suffixed() -> None:
    n = names("release/1.0.1")
    assert n["date_tag"] == "nightly-1.0.1-20261112"
    assert n["pointer_tag"] == "nightly-1.0.1"
    assert n["release_tag"] == "nightly-1.0.1-2026.11.12"
    assert n["version"] == "0.0.0-nightly-20261112+release-1.0.1.0123456"
    assert n["cache_scope"] == "nightly-1.0.1"


def test_rings_are_disjoint() -> None:
    main, rel = names("main"), names("release/1.0.1")
    other = names("release/1.0.10")
    for key, own_tag, foreign in (
        ("image_ring_re", "date_tag", ("date_tag",)),
        ("release_ring_re", "release_tag", ("release_tag",)),
    ):
        for ring, n in ((main, main), (rel, rel), (other, other)):
            assert re.search(ring[key], n[own_tag]), (key, ring[key], n[own_tag])
        for ring, others in ((main, (rel, other)), (rel, (main, other)), (other, (main, rel))):
            for o in others:
                for f in foreign:
                    assert not re.search(ring[key], o[f]), (key, ring[key], o[f])
    # The pointers are in no ring: they must never be pruned.
    for n in (main, rel):
        assert not re.search(n["image_ring_re"], n["pointer_tag"])


@pytest.mark.parametrize(
    "ref", ["", "dev", "release/1.0", "release/1.0.1/x", "release/1.0.1;x", "feature/1.0.1", "main2"]
)
def test_bad_refs_are_refused(ref: str) -> None:
    r = subprocess.run(["bash", str(SCRIPT), ref or "x", "20261112", SHA], capture_output=True)
    assert r.returncode != 0


def test_version_stays_an_unknown_version() -> None:
    # Load the module by path: importing ``app`` pulls in pydantic.
    spec = importlib.util.spec_from_file_location(
        "versions_under_test", REPO / "backend" / "app" / "core" / "versions.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # @dataclass resolves annotations via sys.modules
    spec.loader.exec_module(mod)
    includes_release, nightly_build_date, parse_release = (
        mod.includes_release,
        mod.nightly_build_date,
        mod.parse_release,
    )

    for ref in ("main", "release/1.0.1"):
        v = names(ref)["version"]
        assert parse_release(v) is None  # never a known release, so never "newer"
        assert nightly_build_date(v) is not None
        assert includes_release(v, "1.0.0") is None
