"""The first heartbeat must not add a helm revision for nothing (#1005).

helm-controller MERGES a ``HelmChartConfig`` on top of the same-named
``HelmChart``.  Since #1003 item 4 firstboot renders the control plane sized
to the node — the same numbers the supervisor computes — so the CR the first
heartbeat wrote carried nothing the Chart did not already say.  No Deployment
changed, but helm still recorded revision 2, ran a second helm-install Job,
and left ``helm history`` reading as though something happened.

``_helmchartconfig_upsert`` could not catch that: its idempotence is against
the CR's own previous body, and on a fresh boot there is none.  The guard has
to compare against the **HelmChart**, which is what these tests pin.

Two halves, and both are needed:

* the guard itself — skip only when merging the supervisor's keys in leaves
  the EFFECTIVE values (``deep_merge(chart, config)``) exactly as they are,
  and never when the answer is unknown; and
* :func:`test_firstboot_values_already_satisfy_the_supervisor_overrides`,
  which renders firstboot's actual manifest and asserts the guard *fires* on
  a fresh install.  Without that second half the guard is dead code the first
  time someone adds an override key firstboot does not render — which is
  exactly how this bug was introduced.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import yaml

from spatium_supervisor import k8s_api


# --------------------------------------------------------------------------
# stubs
# --------------------------------------------------------------------------
class _Kube:
    """Minimal kubeapi stand-in that tells the two CR kinds apart.

    The pre-existing ``_Recorder`` in ``test_slot_image_mirror_overrides``
    answers every GET from one document, which was fine while only the
    HelmChartConfig was read.  This one routes by path so a test can say
    "the Chart carries X and there is no Config yet" — the fresh-install
    shape the whole issue is about.
    """

    def __init__(self, *, chart: str | None = None, config: str | None = None):
        self.chart = chart
        self.config = config
        self.calls: list[tuple[str, str]] = []
        self.bodies: list[bytes] = []

    def __call__(self, method, path, body=None, content_type=None):
        self.calls.append((method, path))
        if method == "GET":
            # ``/helmcharts/`` and ``/helmchartconfigs/`` — match the longer
            # one first or every Config read is answered from the Chart.
            doc = self.config if "/helmchartconfigs/" in path else self.chart
            if doc is None:
                return (404, "")
            return (200, json.dumps({"spec": {"valuesContent": doc}}))
        if body is not None:
            self.bodies.append(body)
        return (200 if method == "PATCH" else 201, "{}")

    @property
    def wrote(self) -> bool:
        return any(m in ("POST", "PATCH") for m, _ in self.calls)

    @property
    def written_values(self) -> dict:
        assert self.bodies, "no HelmChartConfig write recorded"
        raw = json.loads(self.bodies[-1])["spec"]["valuesContent"]
        return yaml.safe_load(raw) or {}


def _yaml(doc: dict) -> str:
    return yaml.safe_dump(doc, sort_keys=True, default_flow_style=False)


def _owned(cp_size: int = 1, mem_total_mib: int | None = None) -> dict:
    """What ``apply_control_plane_overrides`` writes on a virgin cluster.

    Captured from the real function rather than restated here, so a new
    override key is covered by these tests the day it is added — restating
    the set is how the guard would go stale without anything going red.
    """
    kube = _Kube(chart=None, config=None)  # nothing exists → it writes
    orig = k8s_api._request
    k8s_api._request = kube  # type: ignore[assignment]
    try:
        ok, err = k8s_api.apply_control_plane_overrides(
            cp_size, "", web_ui_allowed_cidrs=[], mem_total_mib=mem_total_mib
        )
    finally:
        k8s_api._request = orig  # type: ignore[assignment]
    assert (ok, err) == (True, None), (ok, err)
    return kube.written_values


# --------------------------------------------------------------------------
# 1. the guard
# --------------------------------------------------------------------------
def test_skips_the_write_when_the_chart_already_agrees(monkeypatch) -> None:
    chart = _owned()
    kube = _Kube(chart=_yaml(chart), config=None)
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(1, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (False, None)
    assert not kube.wrote, "created a HelmChartConfig that changes nothing"


def test_chart_keys_we_do_not_own_do_not_block_the_skip(monkeypatch) -> None:
    """A Chart carrying extra keys still satisfies us — we own a subset."""
    chart = _owned() | {"global": {"imagePullPolicy": "Never"}, "cnpg": {"enabled": True}}
    kube = _Kube(chart=_yaml(chart), config=None)
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(1, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (False, None)
    assert not kube.wrote


def test_writes_when_a_single_owned_value_differs(monkeypatch) -> None:
    chart = _owned()
    chart["redis"]["sentinel"]["replicas"] = 1
    kube = _Kube(chart=_yaml(chart), config=None)
    monkeypatch.setattr(k8s_api, "_request", kube)

    # cp_size 3 — the promote case the CR exists for.
    ok, err = k8s_api.apply_control_plane_overrides(3, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (True, None)
    assert kube.wrote


def test_writes_when_the_chart_omits_an_owned_key(monkeypatch) -> None:
    """The regression that produced #1005 in the first place.

    A key the supervisor owns and firstboot does not render is a real
    difference, and the guard must not swallow it.
    """
    chart = _owned()
    del chart["slotImageMirror"]
    kube = _Kube(chart=_yaml(chart), config=None)
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(1, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (True, None)
    assert kube.wrote


def test_writes_when_the_chart_cannot_be_read(monkeypatch) -> None:
    """Unknown is not "already agrees".

    Suppressing a needed override is strictly worse than writing a redundant
    one, so an unreadable Chart falls through to today's behaviour.
    """

    def half_broken(method, path, body=None, content_type=None):
        if method == "GET" and "/helmcharts/" in path:
            return (500, "boom")
        if method == "GET":
            return (404, "")
        return (201, "{}")

    monkeypatch.setattr(k8s_api, "_request", half_broken)
    ok, err = k8s_api.apply_control_plane_overrides(1, "", web_ui_allowed_cidrs=[])
    assert (ok, err) == (True, None)


def test_a_chart_bump_config_does_not_pull_the_write_into_the_upgrade(
    monkeypatch,
) -> None:
    """The guard must not be create-only.

    ``chart_bump._patch_image_tag`` CREATES this CR carrying only
    ``image.tag`` to roll the control plane to a new version. A create-only
    guard is bypassed from the next heartbeat onward — at most 30 s later,
    i.e. while the tag-bump apply is still in flight — and PATCHes every
    owned key in. That would not merely fail to remove the redundant write,
    it would move it to the worst possible moment: before #1005 it did not
    happen at all, because the CR already carried those keys.
    """
    chart = _owned()
    kube = _Kube(chart=_yaml(chart), config=_yaml({"image": {"tag": "2026.09.09-1"}}))
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(1, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (False, None)
    assert not kube.wrote, "wrote the owned keys in mid-upgrade"


def test_a_real_change_still_writes_through_an_existing_config(monkeypatch) -> None:
    """...and the skip never suppresses an override that is actually needed.

    A promote is the case that matters: the Chart cannot know ``cp_size``, so
    from the first one the Config is permanently ahead of it.
    """
    chart = _owned()
    kube = _Kube(chart=_yaml(chart), config=_yaml({"image": {"tag": "2026.09.09-1"}}))
    monkeypatch.setattr(k8s_api, "_request", kube)

    ok, err = k8s_api.apply_control_plane_overrides(3, "", web_ui_allowed_cidrs=[])

    assert (ok, err) == (True, None)
    written = kube.written_values
    assert written["api"]["replicas"] == 3
    # ...carrying the key we do not own through untouched.
    assert written["image"] == {"tag": "2026.09.09-1"}


# --------------------------------------------------------------------------
# 2. the guard actually fires on a fresh install
# --------------------------------------------------------------------------
def _firstboot() -> Path:
    """Locate spatiumddi-firstboot by walking up to the repo root.

    RAISES rather than skipping, for the reason spelled out in
    ``test_control_plane_sizing._firstboot``: a cross-repo-boundary test that
    quietly skips reports a clean pass while checking nothing.
    """
    rel = "appliance/mkosi.extra/usr/local/bin/spatiumddi-firstboot"
    for parent in Path(__file__).resolve().parents:
        candidate = parent / rel
        if candidate.is_file():
            return candidate
    raise AssertionError(f"could not find {rel} above {__file__}")


def _memtotal_mib() -> int | None:
    """The same number firstboot's ``_mem_total_mib`` will read.

    Both sides must be given the same input or the comparison measures the
    runner's RAM rather than the two implementations.  ``test_control_plane_
    sizing`` already pins the arithmetic across ten sizes; this test is about
    which KEYS are rendered, so reading the real value is enough.
    """
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(int(line.split()[1]) / 1024)
    except OSError:
        # No /proc — a developer mac. Fall through to None, which is what
        # firstboot's own `_mem_total_mib` yields there too, so both sides
        # still see the same input and the comparison stays meaningful.
        return None
    return None


def _render_firstboot_control_values() -> dict:
    """Run firstboot's own ``_render_control_helmchart`` and parse its output.

    Executed, not pattern-matched: the point is the exact key set the shipped
    manifest carries, and a regex over the heredoc would pass on a key that
    is written but never interpolated.
    """
    src = _firstboot().read_text(encoding="utf-8")
    fn = re.search(r"^_render_control_helmchart\(\) \{.*?^\}$", src, re.S | re.MULTILINE)
    assert fn, "firstboot no longer defines _render_control_helmchart"

    script = f"""
        set -euo pipefail
        {fn.group(0)}
        SPATIUMDDI_VERSION=0.0.0-test
        APP_KEY_SECRET=spatium-control-app-keys
        CHART_APP_SECRET=spatium-control-spatiumddi-app
        DNS_AGENT_KEY_VAL=x
        DHCP_AGENT_KEY_VAL=x
        LG_AGENT_KEY_VAL=x
        APPLIANCE_HOSTNAME_VAL=test
        APPLIANCE_HOST_IPS_VAL=10.0.0.1
        INITIAL_NTP_SERVERS_VAL=""
        CHART_TGZ=/nonexistent
        _render_control_helmchart "Y2hhcnQ="
    """
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True
    ).stdout
    manifest = yaml.safe_load(out)
    values = yaml.safe_load(manifest["spec"]["valuesContent"])
    assert isinstance(values, dict) and values, "firstboot rendered no values"
    return values


def test_firstboot_values_already_satisfy_the_supervisor_overrides() -> None:
    """The fresh-install case: the guard must fire.

    This is the half that keeps #1005 fixed.  Add an override key the
    supervisor owns without rendering it in firstboot and every install goes
    back to two helm revisions — silently, because nothing else looks.
    """
    chart_values = _render_firstboot_control_values()
    owned = _owned(cp_size=1, mem_total_mib=_memtotal_mib())

    merged = k8s_api._deep_merge(chart_values, owned)
    if merged != chart_values:
        differing = sorted(k for k in owned if merged.get(k) != chart_values.get(k))
        raise AssertionError(
            "firstboot does not render every value the supervisor overrides, so "
            "the first heartbeat still adds a helm revision (#1005). Keys that "
            f"differ: {differing}\\n"
            f"supervisor: { {k: owned[k] for k in differing} }\\n"
            f"firstboot:  { {k: chart_values.get(k) for k in differing} }"
        )
