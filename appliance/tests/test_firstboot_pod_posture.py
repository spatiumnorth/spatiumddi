"""firstboot's rendered manifests carry the #983 posture bits.

Two things ``spatiumddi-firstboot`` emits that nothing else can:

  * the ``spatium`` Namespace's Pod Security Admission labels — the chart
    deliberately does NOT own the namespace (a chart-owned namespace is what
    ``spatiumddi-helm-stuck-recover`` exists to clean up after), so the
    labels can only come from here;

  * ``global.priorityClassName`` in the ``spatium-control`` HelmChart's
    values, which is what makes the umbrella chart's control-plane
    workloads pick up the ``spatium-control-plane`` class that the
    spatiumddi-appliance chart renders.

The second one has a hazard worth several tests: a pod naming a
PriorityClass that does not exist is REFUSED by the apiserver — the
Deployment is accepted and the ReplicaSet controller then cannot create
pods. The class comes from a *different* release (spatium-bootstrap), so
there are two gates, and both negative cases are asserted here rather than
reasoned about:

  * render time can only see whether the appliance chart's TARBALL exists;
  * ``release_control_manifest`` re-checks against the live cluster and
    strips the reference when the class is not there, so a failed bootstrap
    release costs the ranking rather than the whole control plane.

The stripper is a ``sed`` pattern that has to keep matching what the
renderer emits — a coupling that would otherwise rot silently, so the round
trip is exercised end to end.

Both renderers sit BELOW the ``SPATIUM_FIRSTBOOT_LIB`` early-return, so
they cannot be reached by sourcing the script the way
``test_firstboot_member_guard.py`` does. They are extracted by name and
evaluated on their own instead; ``_extract_function`` fails loudly if the
name is not found, so a rename shows up as an error rather than as a
vacuously passing test.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_firstboot_pod_posture.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

SCRIPT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-firstboot"
)


def _extract_function(name: str) -> str:
    """Return the shell source of a top-level ``name() { ... }`` function.

    Brace-matched from the opening line to a closing ``}`` at column 0,
    which is how every function in this script is written.
    """
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    opener = f"{name}() {{"
    for i, line in enumerate(lines):
        if line == opener:
            break
    else:  # pragma: no cover - the assert below is the real reporter
        raise AssertionError(f"{name}() not found in {SCRIPT} (renamed?)")
    for j in range(i + 1, len(lines)):
        if lines[j] == "}":
            return "\n".join(lines[i : j + 1])
    raise AssertionError(f"{name}() has no closing brace at column 0")


def _run(func_name: str, env: dict[str, str] | None = None) -> str:
    """Define one extracted function in a fresh shell and call it."""
    body = _extract_function(func_name)
    script = f"{body}\n{func_name}\n"
    proc = subprocess.run(
        ["bash", "-c", script],
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"{func_name} exited {proc.returncode}: {proc.stderr}"
    assert proc.stdout.strip(), f"{func_name} rendered nothing"
    return proc.stdout


# ── Namespace ───────────────────────────────────────────────────────────────


def test_namespace_carries_psa_warn_and_audit() -> None:
    doc = yaml.safe_load(_run("_render_namespace_yaml"))
    assert doc["kind"] == "Namespace"
    assert doc["metadata"]["name"] == "spatium"
    labels = doc["metadata"]["labels"]
    assert labels["pod-security.kubernetes.io/warn"] == "baseline"
    assert labels["pod-security.kubernetes.io/audit"] == "baseline"


def test_namespace_never_enforces() -> None:
    """``enforce`` would reject the role DaemonSets, the supervisor and the
    hostNetwork frontend — every one of which violates ``baseline`` on
    purpose. Report-only is the only mode this namespace can carry."""
    doc = yaml.safe_load(_run("_render_namespace_yaml"))
    assert "pod-security.kubernetes.io/enforce" not in doc["metadata"]["labels"]


# ── Control-plane HelmChart values ──────────────────────────────────────────


def _control_values(chart_tgz: Path | None) -> dict:
    env = {"CHART_TGZ": str(chart_tgz) if chart_tgz else "/nonexistent/appliance.tgz"}
    doc = yaml.safe_load(_run("_render_control_helmchart", env))
    assert doc["kind"] == "HelmChart"
    return yaml.safe_load(doc["spec"]["valuesContent"])


def test_control_plane_workloads_get_the_priority_class(tmp_path: Path) -> None:
    tgz = tmp_path / "spatiumddi-appliance.tgz"
    tgz.write_bytes(b"not really a chart, only its presence is read")
    values = _control_values(tgz)
    assert values["global"]["priorityClassName"] == "spatium-control-plane"


def test_no_priority_class_when_the_chart_that_defines_it_is_absent() -> None:
    """The class is rendered by the spatiumddi-appliance chart. With that
    chart missing there is nothing to define it, and naming it anyway leaves
    the ReplicaSet controller unable to create a single control-plane pod."""
    values = _control_values(None)
    assert values["global"]["priorityClassName"] == ""


def test_the_node_selector_gate_still_renders(tmp_path: Path) -> None:
    """#272's control-plane node gate shares the ``global`` block the
    priority knob was added to; a bad edit there would drop it silently and
    schedule control-plane pods onto DNS-only nodes (non-negotiable #16)."""
    tgz = tmp_path / "chart.tgz"
    tgz.write_bytes(b"x")
    values = _control_values(tgz)
    assert values["global"]["controlPlaneNodeSelector"] == {
        "spatium.io/role-control-plane": "true"
    }


# ── The render functions must emit ONLY the manifest ────────────────────────
#
# `_render_control_helmchart`'s STDOUT IS THE MANIFEST — the caller runs it
# inside `{ ... } > "$tmp"`. A stray `echo` is therefore captured into
# spatium-control.yaml, and the damage depends on the text: one containing
# ": " parses as a junk top-level key on the HelmChart CR (survivable, and
# invisible to every test that asserts only on named keys), while one WITHOUT
# a colon makes the whole document unparseable — k3s cannot decode it,
# spatium-control never installs, and the control plane never comes up.
#
# That shipped: #1003 item 4 added two progress lines here, and the
# MemTotal-unreadable branch was the fatal one. The tests that were supposed
# to cover item 4 were structural string matches against the source, so they
# saw nothing. These render and parse instead.


def test_control_manifest_has_no_stray_top_level_keys() -> None:
    doc = yaml.safe_load(_run("_render_control_helmchart"))
    assert set(doc) == {"apiVersion", "kind", "metadata", "spec"}, (
        f"stray top-level keys {sorted(set(doc) - {'apiVersion','kind','metadata','spec'})} "
        f"— something echoed to stdout inside the render function, and stdout "
        f"is the manifest"
    )


def test_control_manifest_parses_when_memtotal_is_unreadable(tmp_path: Path) -> None:
    """The branch that made the document undecodable.

    Driven by pointing the reader at a nonexistent file, which is what an
    unreadable /proc/meminfo amounts to. Must still be valid YAML AND must
    leave the chart's own sizing defaults in place.
    """
    body = _extract_function("_render_control_helmchart")
    # Neutralise the MemTotal read the same way a missing /proc/meminfo would.
    body = body.replace("/proc/meminfo", str(tmp_path / "no-such-meminfo"))
    # #2240 — and the CPU count, which sizes the CPU limits on its own: with
    # neither readable, nothing is sized at all.
    nproc = "nproc 2>/dev/null || true"
    assert nproc in body, "firstboot's CPU count read moved"
    proc = subprocess.run(
        ["bash", "-c", f"{body.replace(nproc, 'true')}\n_render_control_helmchart\n"],
        env={**os.environ, "CHART_TGZ": "/nonexistent/appliance.tgz"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    doc = yaml.safe_load(proc.stdout)  # raises ScannerError on the bug
    assert set(doc) == {"apiVersion", "kind", "metadata", "spec"}
    values = yaml.safe_load(doc["spec"]["valuesContent"])
    assert "resources" not in (values.get("api") or {}), (
        "with MemTotal unreadable the chart's own defaults must stand"
    )

    # With only the CPU count readable the document is still valid, and the
    # api carries the CPU limit alone.
    proc = subprocess.run(
        ["bash", "-c", f"{body.replace(nproc, 'echo 8')}\n_render_control_helmchart\n"],
        env={**os.environ, "CHART_TGZ": "/nonexistent/appliance.tgz"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    doc = yaml.safe_load(proc.stdout)
    assert set(doc) == {"apiVersion", "kind", "metadata", "spec"}
    values = yaml.safe_load(doc["spec"]["valuesContent"])
    assert values["api"]["resources"] == {"limits": {"cpu": "2000m"}}
    assert values["postgresql"]["resources"] == {"limits": {"cpu": "4000m"}}


def test_control_manifest_carries_the_sizing_when_memtotal_is_readable() -> None:
    """The other half: the fragment must actually land inside `api:`."""
    doc = yaml.safe_load(_run("_render_control_helmchart"))
    values = yaml.safe_load(doc["spec"]["valuesContent"])
    assert values["api"]["resources"]["limits"]["memory"].endswith("Mi")
    assert values["worker"]["concurrency"] in (2, 4)


def test_extractor_reports_a_missing_function() -> None:
    """Negative control for the harness itself: if ``_extract_function``
    quietly returned an empty string for an unknown name, every test above
    would pass against nothing at all."""
    with pytest.raises(AssertionError, match="not found"):
        _extract_function("_render_no_such_thing")


# ── The release-time gate ───────────────────────────────────────────────────


def _render_control_manifest(tmp_path: Path, *, chart_present: bool) -> Path:
    tgz = tmp_path / "spatiumddi-appliance.tgz"
    if chart_present:
        tgz.write_bytes(b"x")
    out = tmp_path / "spatium-control.yaml.deferred"
    out.write_text(_run("_render_control_helmchart", {"CHART_TGZ": str(tgz)}))
    return out


def _strip(manifest: Path) -> dict:
    """Run the real ``_strip_control_priority_class`` over a real render."""
    body = _extract_function("_strip_control_priority_class")
    proc = subprocess.run(
        ["bash", "-c", f'{body}\n_strip_control_priority_class "{manifest}"'],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    doc = yaml.safe_load(manifest.read_text())
    return yaml.safe_load(doc["spec"]["valuesContent"])


def test_stripper_matches_what_the_renderer_emits(tmp_path: Path) -> None:
    """The coupling that would rot silently: a sed pattern on one side, a
    heredoc on the other. Assert the round trip, not either half."""
    m = _render_control_manifest(tmp_path, chart_present=True)
    before = yaml.safe_load(yaml.safe_load(m.read_text())["spec"]["valuesContent"])
    assert before["global"]["priorityClassName"] == "spatium-control-plane"
    after = _strip(m)
    assert after["global"]["priorityClassName"] == ""


def test_stripping_leaves_the_rest_of_the_values_intact(tmp_path: Path) -> None:
    """An over-broad pattern would be worse than no pattern — this manifest
    carries the agent PSKs, the node-selector gate and the cp-size markers."""
    m = _render_control_manifest(tmp_path, chart_present=True)
    before = yaml.safe_load(yaml.safe_load(m.read_text())["spec"]["valuesContent"])
    after = _strip(m)
    before["global"]["priorityClassName"] = ""
    assert after == before


def test_stripping_is_idempotent(tmp_path: Path) -> None:
    """It runs on every boot that cannot confirm the class."""
    m = _render_control_manifest(tmp_path, chart_present=False)
    assert _strip(m)["global"]["priorityClassName"] == ""
    assert _strip(m)["global"]["priorityClassName"] == ""


def test_every_release_site_goes_through_the_gate() -> None:
    """Three code paths release the deferred manifest — the CNPG-webhook
    wait, the host-migrate failure path and the k3s-never-ready path. A bare
    ``mv`` at any of them puts the un-checked value straight into effect."""
    body = SCRIPT.read_text(encoding="utf-8")
    gate = _extract_function("release_control_manifest")
    outside = body.replace(gate, "")
    # A release moves FROM the deferred path INTO $CONTROL_MANIFEST. Writing
    # the deferred file (``mv "$tmp" "${CONTROL_MANIFEST}.deferred"``) is the
    # other direction and is fine.
    offenders = [
        ln.strip()
        for ln in outside.splitlines()
        if ln.strip().startswith("mv ")
        and "deferred" in ln
        and ln.rstrip().endswith('"$CONTROL_MANIFEST"')
    ]
    assert offenders == [], (
        f"deferred manifest released outside release_control_manifest: {offenders}"
    )
    # ...and the gate is actually reached: its definition plus three callers.
    assert body.count("release_control_manifest") >= 4


def test_the_gate_negative_control() -> None:
    """The scan above must actually be able to fail, or it is decoration."""
    gate = _extract_function("release_control_manifest")
    assert 'mv -f "$deferred" "$CONTROL_MANIFEST"' in gate, (
        "the one legitimate release moved or was renamed — the scan in the "
        "test above keys off exactly this shape and would now pass vacuously"
    )


# ── the worker ServiceAccount (#983 Phase 2 item 7) ─────────────────────────


def test_worker_gets_a_service_account(tmp_path: Path) -> None:
    """Alert evaluation runs in the WORKER. Without a ServiceAccount mounted
    there the node_pressure PSI rule evaluates to nothing forever while
    sitting enabled in the Alerts UI — and the appliance is the only place
    that rule can fire at all, so this overlay is what makes it real rather
    than merely possible."""
    values = _control_values(_written(tmp_path))
    assert values["worker"]["serviceAccount"]["enabled"] is True


def test_the_api_service_account_is_untouched(tmp_path: Path) -> None:
    """The worker's SA is a separate, narrower grant — adding it must not
    have disturbed the api's, which the Fleet UI and cert flows depend on."""
    values = _control_values(_written(tmp_path))
    assert values["api"]["serviceAccount"]["enabled"] is True


def _written(tmp_path: Path) -> Path:
    tgz = tmp_path / "spatiumddi-appliance.tgz"
    tgz.write_bytes(b"x")
    return tgz
