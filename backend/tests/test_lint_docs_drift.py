"""The docs drift check (#3414).

``scripts/lint_docs_drift.py`` compares docs diagrams and pages against the
code. These tests build a small synthetic repo in ``tmp_path`` -- one that
passes, and one failure per check kind -- rather than reading the real tree:
the real tree is what the weekly workflow runs the script against, and it is
*known* to carry drift while #3413 fixes it, so a test over it would be red
or, worse, quietly allowlisted.

The negative cases matter most. This repo has been bitten by a guard that
evaluated nothing and printed the same line as success (#1028-#1030), so the
tests pin that an empty inventory, a missing manifest, or an allowlist entry
that matches nothing is an error rather than a pass.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import types

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "lint_docs_drift.py"

# The dev container copies only ``backend/`` into the image, so this skips
# there and runs for real in CI (same convention as test_lint_versions.py).
pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists(),
    reason="docs drift linter not present in this checkout",
)


@pytest.fixture(scope="module")
def lint() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("lint_docs_drift", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SERVICES = [
    "postgres",
    "redis",
    "api",
    "worker",
    "beat",
    "frontend",
    "dns-bind9",
    "dhcp-kea",
]

MANIFEST = {
    "architecture_diagram": "docs/assets/architecture.svg",
    "version_labels": {
        "redis": r"\bRedis\s+v?((?:[4-9]|\d{2,})(?:\.\d+)*)",
        "bind": r"\bBIND(?:\s?9)?\s+(9\.\d+(?:\.\d+)*)",
        "alpine": r"\b[Aa]lpine[\s:]+(\d+\.\d+(?:\.\d+)*)",
    },
    "needles": {"compose:postgres": ["postgresql"], "agent:dns": ["spatium dns agent"]},
    "inventory_allowlist": {"compose:migrate": "one-shot job"},
    "inventory_regions": {
        "dns-driver": {"from": "Data plane", "to": "Integration mirrors"},
        "dhcp-driver": {"from": "Data plane", "to": "Integration mirrors"},
        "integration": {"from": "Integration mirrors"},
    },
    "identifier_diagrams": {
        "docs/assets/diagrams/model.svg": ["backend/app/models/dns.py"]
    },
    "identifier_ignore": {},
    "path_roots": ["backend", "agent", "docs"],
}

# Names every inventory item, so the tree starts clean.
ARCH_TEXT = [
    "PostgreSQL 16",
    "Redis 8",
    "API",
    "Worker",
    "Beat",
    "Frontend",
    "spatium-dns-agent",
    "Looking Glass",
    "Data plane",
    "dns-bind9",
    "BIND9 9.20",
    "dhcp-kea",
    "Integration mirrors",
    "Docker",
]


def _svg(texts: list[str]) -> str:
    body = "".join(f'<text x="1" y="{i}">{t}</text>' for i, t in enumerate(texts))
    return f'<svg xmlns="http://www.w3.org/2000/svg">{body}</svg>'


def _write(root: pathlib.Path, rel: str, body: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


def build(root: pathlib.Path, **override: object) -> pathlib.Path:
    """A repo that passes every check. ``override`` replaces a manifest key."""
    manifest = {**MANIFEST, **override}
    _write(root, "scripts/docs_drift_manifest.json", json.dumps(manifest))
    _write(
        root,
        "versions.json",
        json.dumps(
            {
                "components": {
                    "redis": {"version": "8.10.2-alpine"},
                    "bind": {"version": "9.20.29-r0"},
                    "alpine": {"version": "3.24"},
                }
            }
        ),
    )
    compose = "services:\n" + "".join(
        f"  {s}:\n    image: x\n" for s in [*SERVICES, "migrate"]
    )
    _write(root, "docker-compose.yml", compose + "volumes:\n  data:\n")
    for chart in ("spatiumddi", "spatiumddi-appliance"):
        (root / "charts" / chart / "templates").mkdir(parents=True, exist_ok=True)
    _write(
        root,
        "charts/spatiumddi/templates/api.yaml",
        'kind: Deployment\nmetadata:\n  name: {{ include "x.fullname" . }}-api\n',
    )
    _write(
        root,
        "charts/spatiumddi-appliance/templates/looking-glass.yaml",
        "kind: DaemonSet\nmetadata:\n  name: looking-glass\n",
    )
    (root / "agent" / "dns").mkdir(parents=True, exist_ok=True)
    _write(root, "backend/app/drivers/dns/bind9.py", "")
    _write(root, "backend/app/drivers/dns/base.py", "")
    _write(root, "backend/app/drivers/dns/_private.py", "")
    _write(root, "backend/app/drivers/dhcp/kea.py", "")
    _write(
        root,
        "backend/app/services/feature_modules.py",
        'ModuleSpec(\n    id="integrations.docker",\n)\n',
    )
    _write(
        root,
        "backend/app/models/dns.py",
        "class DNSRecordOp(Base):\n"
        '    __tablename__ = "dns_record_op"\n'
        "    target_serial: Mapped[int]\n"
        "    zone_name: Mapped[str]\n",
    )
    _write(root, "docs/assets/architecture.svg", _svg(ARCH_TEXT))
    _write(
        root,
        "docs/assets/diagrams/model.svg",
        _svg(["DNSRecordOp", "dns_record_op", "target_serial", "RecordOp"]),
    )
    _write(root, "docs/guide.md", "Redis 8 and BIND9 9.20 ship.\n")
    return root


def _kinds(findings: list) -> list[str]:
    return sorted(f.kind for f in findings)


def test_clean_tree_has_no_findings(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    assert lint.run(build(tmp_path)) == []


# --- version ---------------------------------------------------------------


def test_stale_version_in_svg_and_page(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path)
    _write(
        tmp_path,
        "docs/assets/architecture.svg",
        _svg([*ARCH_TEXT, "Redis 7", "BIND9 9.18"]),
    )
    _write(tmp_path, "docs/guide.md", "Pins Redis 7 today.\n")
    msgs = [f.line() for f in lint.run(tmp_path) if f.kind == "version"]
    assert len(msgs) == 3
    assert any("architecture.svg" in m and "Redis 7" in m for m in msgs)
    assert any("BIND9 9.18" in m for m in msgs)
    assert any("docs/guide.md" in m and "redis 8.10.2-alpine" in m for m in msgs)


def test_a_list_and_a_dockerfile_from_are_not_history(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    """ "and" joins a list of what ships and ``FROM`` is a Dockerfile instruction;
    the first draft read both as history and skipped the version after them."""
    build(tmp_path)
    _write(
        tmp_path,
        "docs/guide.md",
        "Ships BIND9 9.20 and Redis 7.\n```\nFROM alpine:3.23 AS runtime\n```\n",
    )
    msgs = sorted(f.line() for f in lint.run(tmp_path) if f.kind == "version")
    assert msgs == [
        "docs/guide.md: version: line 1: 'Redis 7' but versions.json pins redis 8.10.2-alpine",
        "docs/guide.md: version: line 3: 'alpine:3.23' but versions.json pins alpine 3.24",
    ]


def test_version_granularity_and_history_are_not_findings(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path)
    _write(
        tmp_path,
        "docs/guide.md",
        "Redis 8.10 is fine. BIND 9.20 is fine.\n"
        "Needs BIND 9.18+ for catalog zones.\n"
        "Since Redis 7 the wake bus exists.\n"
        "Upgraded from Redis 6 to Redis 7 last year.\n"
        "Behaviour differs between Redis 6 and Redis 7.\n"
        "Kea 3.0 (shipped from Alpine 3.23) caches leases.\n"
        "CNPG 1 / Redis 1 replicas.\n",
    )
    assert [f for f in lint.run(tmp_path) if f.kind == "version"] == []


def test_a_label_naming_a_component_missing_from_versions_json_is_an_error(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path, version_labels={"nope": r"\bNope\s+(\d+)"})
    with pytest.raises(lint.CheckError):
        lint.run(tmp_path)


# --- inventory -------------------------------------------------------------


def test_unlisted_workloads_are_findings(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path)
    _write(
        tmp_path,
        "docs/assets/architecture.svg",
        _svg(["PostgreSQL 16", "Redis 8", "API", "Data plane", "Integration mirrors"]),
    )
    keys = " ".join(f.message for f in lint.run(tmp_path) if f.kind == "inventory")
    for expected in (
        "compose:dns-bind9",
        "workload:looking-glass",
        "agent:dns",
        "dns-driver:bind9",
        "dhcp-driver:kea",
    ):
        assert expected in keys
    # ...but not what the diagram names, nor the underscore-prefixed / base modules.
    assert "compose:api" not in keys
    assert "_private" not in keys
    assert "dns-driver:base" not in keys


def test_allowlist_exempts_and_a_dead_entry_is_a_finding(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path)
    # compose:migrate is allowlisted and absent from the diagram: no finding.
    assert lint.run(tmp_path) == []
    build(
        tmp_path, inventory_allowlist={"compose:migrate": "x", "compose:ghost": "gone"}
    )
    findings = lint.run(tmp_path)
    assert [f.file for f in findings] == ["scripts/docs_drift_manifest.json"]
    assert "compose:ghost" in findings[0].message


def test_an_allowlist_entry_needs_a_reason(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path, inventory_allowlist={"compose:migrate": " "})
    with pytest.raises(lint.CheckError):
        lint.run(tmp_path)


def test_a_driver_must_be_drawn_in_its_own_region(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    """The FortiGate DHCP driver is not the Fortinet FortiGate integration card."""
    build(tmp_path)
    _write(tmp_path, "backend/app/drivers/dhcp/fortigate.py", "")
    _write(
        tmp_path,
        "docs/assets/architecture.svg",
        _svg([*ARCH_TEXT, "Fortinet FortiGate", "integrations · docker"]),
    )
    msgs = [f.message for f in lint.run(tmp_path) if f.kind == "inventory"]
    assert len(msgs) == 1
    assert "dhcp-driver:fortigate" in msgs[0] and "'Data plane' section" in msgs[0]

    texts = list(ARCH_TEXT)
    texts.insert(texts.index("Integration mirrors"), "FortiGate DHCP")
    _write(tmp_path, "docs/assets/architecture.svg", _svg(texts))
    assert lint.run(tmp_path) == []

    # An integration named only by the Worker's generic 'integrations' line, above
    # the mirrors lane, is not drawn: any new integration would otherwise pass.
    texts.remove("Docker")
    texts.insert(0, "integrations · docker")
    _write(tmp_path, "docs/assets/architecture.svg", _svg(texts))
    msgs = [f.message for f in lint.run(tmp_path) if f.kind == "inventory"]
    assert len(msgs) == 1 and "integration:docker" in msgs[0]


def test_a_region_heading_that_moved_cannot_run(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path)
    _write(
        tmp_path,
        "docs/assets/architecture.svg",
        _svg([t for t in ARCH_TEXT if t != "Integration mirrors"]),
    )
    with pytest.raises(lint.CheckError):
        lint.run(tmp_path)


def test_an_empty_inventory_is_an_error_not_a_pass(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path)
    (tmp_path / "docker-compose.yml").write_text("services:\n")
    for p in (tmp_path / "charts").rglob("*.yaml"):
        p.unlink()
    with pytest.raises(lint.CheckError):
        lint.run(tmp_path)


# --- identifier ------------------------------------------------------------


def test_identifier_missing_from_models(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path)
    _write(
        tmp_path,
        "docs/assets/diagrams/model.svg",
        _svg(
            [
                "serial_strategy: bump",
                "target_serial",
                "DNSRecordOp",
                "RecordOp",
                "env AGENT_KEY",
            ]
        ),
    )
    found = [f for f in lint.run(tmp_path) if f.kind == "identifier"]
    assert len(found) == 1
    assert "serial_strategy" in found[0].message and found[0].file.endswith("model.svg")


def test_identifier_ignore_and_unmapped_diagrams(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path, identifier_ignore={"serial_strategy": "a JSON key"})
    _write(tmp_path, "docs/assets/diagrams/model.svg", _svg(["serial_strategy"]))
    _write(tmp_path, "docs/assets/diagrams/other.svg", _svg(["no_such_thing"]))
    assert [f for f in lint.run(tmp_path) if f.kind == "identifier"] == []


def test_a_dead_identifier_ignore_is_a_finding(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path, identifier_ignore={"gone_name": "was a JSON key"})
    found = [f for f in lint.run(tmp_path) if f.kind == "identifier"]
    assert [f.file for f in found] == ["scripts/docs_drift_manifest.json"]
    assert "gone_name" in found[0].message


def test_identifier_mapped_module_must_exist(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(
        tmp_path,
        identifier_diagrams={
            "docs/assets/diagrams/model.svg": ["backend/app/models/gone.py"]
        },
    )
    with pytest.raises(lint.CheckError):
        lint.run(tmp_path)


# --- path ------------------------------------------------------------------


def test_paths_named_in_diagrams_must_exist(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    build(tmp_path)
    _write(
        tmp_path,
        "docs/assets/diagrams/paths.svg",
        _svg(
            [
                "backend/app/models/dns.py",
                "backend/app/models/gone.py",
                "backend/app/drivers/*.py",
                "docs/guide",
                "/var/lib/runtime/state.json",
                "missing-file.yml",
            ]
        ),
    )
    found = sorted(f.message for f in lint.run(tmp_path) if f.kind == "path")
    assert len(found) == 2
    assert (
        "backend/app/models/gone.py" in found[0]
        or "backend/app/models/gone.py" in found[1]
    )
    assert any("missing-file.yml" in m for m in found)


# --- plumbing --------------------------------------------------------------


def test_missing_or_misspelt_manifest_is_an_error(
    lint: types.ModuleType, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(lint.CheckError):
        lint.load_manifest(tmp_path)
    build(tmp_path, identifer_ignore={})
    with pytest.raises(lint.CheckError):
        lint.load_manifest(tmp_path)


def test_exit_codes_and_markdown(
    lint: types.ModuleType, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    build(tmp_path)
    assert lint.main(["--root", str(tmp_path)]) == 0
    assert lint.main(["--root", str(tmp_path), "--markdown"]) == 0
    assert capsys.readouterr().out == ""  # clean: no body, so nothing to file

    _write(tmp_path, "docs/guide.md", "Redis 7\n")
    assert lint.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert out.strip() == (
        "docs/guide.md: version: line 1: 'Redis 7' but versions.json pins redis 8.10.2-alpine"
    )
    assert lint.main(["--root", str(tmp_path), "--markdown"]) == 1
    body = capsys.readouterr().out
    assert (
        body.startswith(lint.MARKER)
        and "### version (1)" in body
        and "docs/guide.md" in body
    )

    (tmp_path / "scripts/docs_drift_manifest.json").unlink()
    assert lint.main(["--root", str(tmp_path)]) == 2
