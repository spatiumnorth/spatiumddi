"""No appliance unit starts k3s as a side effect (#1723).

k3s.service is enabled in its own right and multi-user.target starts it at
boot. The runners that stop it on purpose (the cluster join and leave runner,
the slot upgrade, the restore) start it again themselves once they are done.
A unit that pulls k3s.service in (Wants=, Requires=, BindsTo=, Upholds=,
OnSuccess=, OnFailure=), or a .path or .timer that names it as its Unit=,
starts k3s whenever that unit is triggered, including while a runner holds
it stopped. On a joining node that k3s came up on the standalone config with
the identity gone, founded a one-node cluster of its own, and the join still
logged JOIN ok. A unit that must run after k3s orders itself with After=.

    python3 -m pytest appliance/tests/test_units_never_start_k3s.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
UNIT_DIRS = [
    REPO / "appliance" / "mkosi.extra" / "etc" / "systemd" / "system",
    REPO / "appliance" / "mkosi.extra" / "usr" / "lib" / "systemd" / "system",
]
K3S = "k3s.service"
PULLS = ("Wants", "Requires", "BindsTo", "Upholds", "OnSuccess", "OnFailure")
UNIT_SUFFIXES = (".service", ".path", ".timer", ".socket", ".target", ".mount")
# The units that once pulled k3s in (#1723); each must still order after it.
ORDERED_AFTER_K3S = (
    "spatiumddi-publish-k3s-token.service",
    "spatiumddi-helm-stuck-recover.service",
    "spatiumddi-image-prune.service",
)

pytestmark = pytest.mark.skipif(
    not UNIT_DIRS[0].is_dir(), reason="appliance tree not present in this checkout"
)


def _unit_files() -> list[Path]:
    files: list[Path] = []
    for unit_dir in UNIT_DIRS:
        if not unit_dir.is_dir():
            continue
        for path in sorted(unit_dir.rglob("*")):
            if not path.is_file():
                continue
            drop_in = path.suffix == ".conf" and path.parent.name.endswith(".d")
            if path.name.endswith(UNIT_SUFFIXES) or drop_in:
                files.append(path)
    return files


def _entries(path: Path) -> list[tuple[str, str, str]]:
    """(section, key, value) for every assignment, continuation lines joined."""
    entries: list[tuple[str, str, str]] = []
    section = ""
    text = re.sub(r"\\\n", " ", path.read_text())
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            entries.append((section, key.strip(), value.strip()))
    return entries


def test_the_scan_sees_the_appliance_units() -> None:
    names = {path.name for path in _unit_files()}
    assert K3S in names and set(ORDERED_AFTER_K3S) <= names


def test_no_unit_starts_k3s_as_a_side_effect() -> None:
    offenders = []
    for path in _unit_files():
        if path.name == K3S:
            continue
        for section, key, value in _entries(path):
            pulls = section == "Unit" and key in PULLS
            triggers = section in ("Path", "Timer") and key == "Unit"
            if (pulls or triggers) and K3S in value.split():
                offenders.append(f"{path.relative_to(REPO)}: [{section}] {key}={value}")
    assert not offenders, (
        "these units start k3s whenever they are triggered, including while a "
        "runner holds it stopped (#1723); order with After= instead:\n" + "\n".join(offenders)
    )


@pytest.mark.parametrize("name", ORDERED_AFTER_K3S)
def test_the_units_that_need_k3s_still_order_after_it(name: str) -> None:
    path = UNIT_DIRS[0] / name
    after = [v for s, k, v in _entries(path) if s == "Unit" and k == "After"]
    assert any(K3S in value.split() for value in after), f"{name} lost After={K3S}"
