"""The console's host-config rollup reads the fire-state ledger like the
supervisor does (#2053).

The console is a standalone host script that may not import the supervisor,
so it carries its own copy of the ledger reader and of the plane list. Its
copy stripped the whole line, so a plane turned off (an EMPTY hash, written
``\\t1\\t<iso>``) lost its leading tab, the hash read back as ``"1"``, and the
dashboard reported the plane ``retrying`` forever. The console imports rich
and psutil at load time, which this suite does not install, so these tests
lift the functions out of the shipped script and run exactly those bytes.
"""

from __future__ import annotations

import __future__
import ast
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONSOLE = ROOT / "appliance/mkosi.extra/usr/local/bin/spatium-console"
SUPERVISOR = ROOT / "agent/supervisor/spatium_supervisor/appliance_state.py"
_NAMES = {
    "_HOST_CONFIG_PLANES_DASH",
    "_HOSTCFG_FAILING_ATTEMPTS_DASH",
    "_read_state_line",
    "_read_fire_state_dash",
    "host_health_rollup",
}


def _console(state_dir: Path) -> dict[str, Any]:
    tree = ast.parse(CONSOLE.read_text(encoding="utf-8"))
    body: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            body.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in _NAMES for t in targets):
                body.append(node)
    namespace: dict[str, Any] = {"Path": Path, "json": json}
    code = compile(
        ast.Module(body=body, type_ignores=[]),
        str(CONSOLE),
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    exec(code, namespace)  # noqa: S102 — the shipped console's own functions
    missing = _NAMES - set(namespace)
    assert not missing, f"not found in spatium-console: {sorted(missing)}"
    namespace["_RELEASE_STATE_DIR"] = state_dir
    return namespace


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("abc\t2\t2026-10-01T00:00:00+00:00\n", ("abc", 2, True)),
        ("\t1\t2026-10-01T00:00:00+00:00\n", ("", 1, True)),
        ("\t1\t2026-10-01T00:00:00+00:00\r\n", ("", 1, True)),
        ("abc \t2 \t2026-10-01T00:00:00+00:00  \n", ("abc", 2, True)),
        ("", ("", 0, False)),
        ("   \n", ("", 0, False)),
        ("\t\t\n", ("", 0, False)),
    ],
)
def test_reader_keeps_the_fields_in_place(
    tmp_path: Path, body: str, expected: tuple[str, int, bool]
) -> None:
    ns = _console(tmp_path)
    (tmp_path / "ssh-config-pending.fire-state").write_bytes(body.encode())
    assert ns["_read_fire_state_dash"]("ssh-config-pending") == expected


def test_missing_ledger_is_never_fired(tmp_path: Path) -> None:
    ns = _console(tmp_path)
    assert ns["_read_fire_state_dash"]("ssh-config-pending") == ("", 0, False)


@pytest.mark.parametrize("off_sidecar", ["", "\n"])
def test_plane_turned_off_reads_ok(tmp_path: Path, off_sidecar: str) -> None:
    ns = _console(tmp_path)
    (tmp_path / "ssh-config-pending.fire-state").write_text(
        "\t1\t2026-10-01T00:00:00+00:00\n"
    )
    (tmp_path / "ssh-config-hash").write_text(off_sidecar)
    rollup = ns["host_health_rollup"]()
    assert rollup["verdict"] == "ok"
    assert rollup["retrying"] == [] and rollup["failing"] == []


def test_plane_turned_off_but_unapplied_is_reported(tmp_path: Path) -> None:
    ns = _console(tmp_path)
    (tmp_path / "ssh-config-pending.fire-state").write_text(
        "\t1\t2026-10-01T00:00:00+00:00\n"
    )
    (tmp_path / "ssh-config-hash").write_text("hashA\n")
    assert ns["host_health_rollup"]()["retrying"] == ["ssh"]


def _supervisor_planes() -> list[tuple[str, str, str]]:
    """``appliance_state._HOST_CONFIG_PLANES`` as (name, trigger, sidecar)
    basenames, resolved from the module's ``Path("...")`` constants without
    importing it (the appliance suite does not install its dependencies)."""
    tree = ast.parse(SUPERVISOR.read_text(encoding="utf-8"))
    paths: dict[str, str] = {}
    planes: ast.expr | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        else:
            continue
        if not isinstance(target, ast.Name):
            continue
        if target.id == "_HOST_CONFIG_PLANES":
            planes = value
        elif (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "Path"
            and value.args
            and isinstance(value.args[0], ast.Constant)
        ):
            paths[target.id] = Path(value.args[0].value).name
    assert isinstance(planes, ast.List)
    out = []
    for elt in planes.elts:
        assert isinstance(elt, ast.Tuple)
        name, trig, sidecar = elt.elts
        assert isinstance(name, ast.Constant)
        assert isinstance(trig, ast.Name) and isinstance(sidecar, ast.Name)
        out.append((name.value, paths[trig.id], paths[sidecar.id]))
    return out


def test_console_plane_list_mirrors_the_supervisor(tmp_path: Path) -> None:
    # The console's list said "keep in sync" and had fallen three planes
    # behind (apt, console_mode, removable), so a stuck apply on any of them
    # was invisible at the console while Fleet reported it.
    ns = _console(tmp_path)
    assert sorted(ns["_HOST_CONFIG_PLANES_DASH"]) == sorted(_supervisor_planes())
