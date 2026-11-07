"""#3693 — the api image's Python set must be reproducible.

``pip install .`` against ``pyproject.toml``'s open ranges resolved whatever PyPI
held on the day the builder layer was last invalidated, so two builds of one
commit shipped different packages (redis 6.4.0 vs 8.1.0: ~25 % less ``/health/ready``
throughput). ``backend/requirements.txt`` is the pin set; these tests keep the
Dockerfile installing through it and keep it a valid resolution of pyproject.
Offline resolver check: every dependency (runtime + extras) must have an exact
pin in the file that satisfies the declared specifier.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

BACKEND = Path(__file__).resolve().parents[1]
LOCK = BACKEND / "requirements.txt"
DOCKERFILE = BACKEND / "Dockerfile"
PYPROJECT = BACKEND / "pyproject.toml"

# Skip only where the Dockerfile itself is absent (a context that does not ship
# it). Keying the skip on the lock too would turn deleting requirements.txt —
# the regression this file guards — into a skip instead of a failure.
pytestmark = pytest.mark.skipif(
    not DOCKERFILE.exists(),
    reason="the Dockerfile is not in this tree",
)


def _pins() -> dict[str, Version]:
    pins: dict[str, Version] = {}
    for raw in LOCK.read_text().splitlines():
        line = raw.split("#", 1)[0].strip().rstrip("\\").strip()
        if not line or line.startswith("-"):
            continue
        req = Requirement(line)
        specs = list(req.specifier)
        assert len(specs) == 1 and specs[0].operator == "==", f"{line!r} is not an exact pin"
        name = canonicalize_name(req.name)
        assert name not in pins, f"{name} pinned twice"
        pins[name] = Version(specs[0].version)
    return pins


def _declared() -> list[Requirement]:
    meta = tomllib.loads(PYPROJECT.read_text())["project"]
    reqs = [Requirement(r) for r in meta["dependencies"]]
    for extra in meta.get("optional-dependencies", {}).values():
        reqs.extend(Requirement(r) for r in extra)
    return reqs


def test_dockerfile_installs_through_the_lock() -> None:
    text = DOCKERFILE.read_text()
    runs = re.findall(r"^RUN (?:[^\n]*\\\n)*[^\n]*", text, re.M)
    installs = [r for r in runs if "pip install" in r and "--prefix=/install" in r]
    assert len(installs) == 1, "builder stage must have exactly one `pip install --prefix=/install`"
    cmd = installs[0]
    assert re.search(r"(-c|--constraint)\s+requirements\.txt\b", cmd), (
        "the builder's `pip install .` must pass `-c requirements.txt` (#3693), "
        "or a rebuild of one commit ships a different package set"
    )
    assert re.search(
        r"^COPY pyproject\.toml requirements\.txt \./?$", text, re.M
    ), "requirements.txt must be COPYed beside pyproject.toml before the install layer"


def test_every_declared_dependency_is_pinned_within_its_range() -> None:
    pins = _pins()
    problems = []
    for req in _declared():
        name = canonicalize_name(req.name)
        pin = pins.get(name)
        if pin is None:
            problems.append(f"{req.name}: not pinned in requirements.txt")
        elif not req.specifier.contains(pin, prereleases=True):
            problems.append(f"{req.name}: pin {pin} violates {req.specifier}")
    assert not problems, "requirements.txt disagrees with pyproject.toml:\n" + "\n".join(problems)


def test_every_pin_has_a_reason_to_exist() -> None:
    """The pinned culprit stays the version the soak measured as fast."""
    assert _pins()[canonicalize_name("redis")] < Version("7"), (
        "redis >= 7 cost ~25 % of /health/ready throughput (#3693); "
        "re-measure before raising this pin"
    )


def test_lock_is_generated_not_hand_edited() -> None:
    """uv writes the pins sorted by name. A hand edit (the first cut of this
    file swapped redis 8.1.0 for 6.4.0 by hand and left kombu out of order)
    is a pin the documented command does not reproduce: regenerating would
    silently undo it. The redis hold now lives in pyproject.toml instead."""
    names = list(_pins())
    assert names == sorted(names), "requirements.txt is not in uv's order; regenerate it"
    redis = next(r for r in _declared() if canonicalize_name(r.name) == "redis")
    assert not redis.specifier.contains("7.0.0"), (
        "pyproject.toml must cap redis below 7 (#3693), or regenerating the lock "
        "lifts it to the slower major"
    )
