"""A rendered zone file is worthless if named never reads it back (#704).

``rndc reconfig`` — what ``swap_and_reload`` used to issue on its own — is
defined by BIND as "reload the configuration file and load new zones, but do
not reload existing zone files even if they have changed". That is the right
primitive only while a record edit reaches the daemon some OTHER way. Under
split-horizon (issue #24) it does not: the control plane stops dispatching RFC
2136 record ops for a group with views — an nsupdate to loopback cannot target
a view — and propagates record changes by re-rendering the zone file instead.
``reconfig`` never reads that file, so every record created after the zone's
first load was written to disk and never served.

And because every primary zone carries the group's loopback TSIG grant in
``allow-update`` (``_render_allow_update``: "ALWAYS included"), the zones are
DYNAMIC, and named will not re-read a dynamic zone's file on a plain reload
either — it has to be frozen first. Hence freeze → reload → thaw.
"""

from __future__ import annotations

import subprocess

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver


def _rendered(tmp_path, layout: dict[str | None, list[str]],
              into: str = "rendered") -> Bind9Driver:
    """A driver whose rendered tree carries `layout`.

    `into="rendered.new"` stages it the way `render()` really does, so
    `swap_and_reload` promotes it — reading the tree back after the swap is
    the whole contract `rendered_zone_views` has to honour.
    """
    drv = Bind9Driver(state_dir=tmp_path)
    zones = tmp_path / into / "zones"
    for view, names in layout.items():
        target = zones / view if view else zones
        target.mkdir(parents=True, exist_ok=True)
        for n in names:
            (target / f"{n}.db").write_text("; rendered\n")
    return drv


def test_rendered_zone_views_reads_the_split_horizon_layout(tmp_path):
    drv = _rendered(tmp_path, {
        "meridian-internal": ["lab.ddipg.test", "50.10.10.in-addr.arpa"],
        "meridian-external": ["lab.ddipg.test"],
    })
    assert sorted(drv.rendered_zone_views()) == [
        ("50.10.10.in-addr.arpa", "meridian-internal"),
        ("lab.ddipg.test", "meridian-external"),
        ("lab.ddipg.test", "meridian-internal"),
    ]


def test_rendered_zone_views_reads_the_flat_layout(tmp_path):
    drv = _rendered(tmp_path, {None: ["corp.ddipg.test"]})
    assert drv.rendered_zone_views() == [("corp.ddipg.test", None)]


def test_rendered_zone_views_is_empty_before_a_first_render(tmp_path):
    assert Bind9Driver(state_dir=tmp_path).rendered_zone_views() == []


@pytest.fixture
def rndc_spy(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(cmd, *a, **kw):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/sbin/rndc")
    return calls


def test_swap_and_reload_reloads_each_rendered_zone_not_just_the_config(
    tmp_path, monkeypatch, rndc_spy
):
    drv = _rendered(tmp_path, {"meridian-internal": ["lab.ddipg.test"]},
                    into="rendered.new")
    monkeypatch.setattr(drv, "daemon_running", lambda: True)

    drv.swap_and_reload()

    verbs = [c[1] for c in rndc_spy]
    assert verbs[0] == "reconfig", "config changes still need reconfig"
    # The whole point: the zone itself is reloaded, and frozen first because
    # the loopback TSIG grant makes it dynamic. ``rndc reload`` only queues
    # the load (#1224), so the zone is asked what it serves before and after.
    assert verbs[1:] == ["zonestatus", "freeze", "reload", "thaw", "zonestatus"]
    for call in rndc_spy[1:]:
        assert call[2:] == ["lab.ddipg.test", "in", "meridian-internal"]


def test_swap_and_reload_scopes_a_flat_zone_without_a_view(
    tmp_path, monkeypatch, rndc_spy
):
    drv = _rendered(tmp_path, {None: ["corp.ddipg.test"]}, into="rendered.new")
    monkeypatch.setattr(drv, "daemon_running", lambda: True)

    drv.swap_and_reload()

    assert [c[1] for c in rndc_spy] == [
        "reconfig", "zonestatus", "freeze", "reload", "thaw", "zonestatus"
    ]
    assert rndc_spy[-1][2:] == ["corp.ddipg.test"], "no `in <view>` without views"


def test_a_zone_that_will_not_reload_does_not_block_the_others(
    tmp_path, monkeypatch
):
    """Best-effort by design — one unreloadable zone must not strand the rest."""
    calls: list[list[str]] = []

    def fake_run(cmd, *a, **kw):
        calls.append(list(cmd))
        rc = 1 if cmd[1:3] == ["reload", "a.test"] else 0
        return subprocess.CompletedProcess(cmd, rc, "", "boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/sbin/rndc")
    drv = _rendered(tmp_path, {None: ["a.test", "b.test"]}, into="rendered.new")
    monkeypatch.setattr(drv, "daemon_running", lambda: True)

    drv.swap_and_reload()

    assert ["reload", "b.test"] in [c[1:3] for c in calls]


def test_only_the_zones_whose_bytes_changed_are_reloaded(tmp_path, monkeypatch,
                                                         rndc_spy):
    """The reload must be proportional to the edit.

    A views group re-renders on every record change, so reloading the whole
    tree each time turns one record edit into a freeze/reload/thaw storm across
    every zone. With the deep tiers mutating records continuously that is real
    load on a small appliance, so only the zones that actually moved reload.
    """
    prev = tmp_path / "rendered.prev" / "zones" / "v1"
    prev.mkdir(parents=True)
    (prev / "a.test.db").write_text("; same\n")
    (prev / "b.test.db").write_text("; old\n")
    stage = tmp_path / "rendered.new" / "zones" / "v1"
    stage.mkdir(parents=True)
    (stage / "a.test.db").write_text("; same\n")
    (stage / "b.test.db").write_text("; NEW\n")
    drv = Bind9Driver(state_dir=tmp_path)
    monkeypatch.setattr(drv, "daemon_running", lambda: True)

    drv.swap_and_reload()

    reloaded = [c[2] for c in rndc_spy if c[1] == "reload"]
    assert reloaded == ["b.test"], "a.test was byte-identical; it must not reload"


def test_a_brand_new_zone_reloads(tmp_path, monkeypatch, rndc_spy):
    """A zone with no previous file is a change by definition."""
    (tmp_path / "rendered.prev" / "zones").mkdir(parents=True)
    stage = tmp_path / "rendered.new" / "zones"
    stage.mkdir(parents=True)
    (stage / "fresh.test.db").write_text("; new\n")
    drv = Bind9Driver(state_dir=tmp_path)
    monkeypatch.setattr(drv, "daemon_running", lambda: True)

    drv.swap_and_reload()

    assert [c[2] for c in rndc_spy if c[1] == "reload"] == ["fresh.test"]


def test_no_previous_render_reloads_everything(tmp_path, monkeypatch, rndc_spy):
    """Cold start: with nothing to diff against, reload all of it.

    `None` (cannot tell) and the empty set (nothing moved) must not collapse
    into the same behaviour — that is the difference between a correct cold
    start and a daemon left serving stale zones.
    """
    drv = _rendered(tmp_path, {"v1": ["a.test", "b.test"]}, into="rendered.new")
    monkeypatch.setattr(drv, "daemon_running", lambda: True)

    drv.swap_and_reload()

    assert sorted(c[2] for c in rndc_spy if c[1] == "reload") == ["a.test", "b.test"]


def test_an_unchanged_render_reloads_nothing(tmp_path, monkeypatch, rndc_spy):
    """The storm case, inverted: a no-op re-render must cost no rndc traffic."""
    for d in ("rendered.prev", "rendered.new"):
        p = tmp_path / d / "zones" / "v1"
        p.mkdir(parents=True)
        (p / "a.test.db").write_text("; same\n")
    drv = Bind9Driver(state_dir=tmp_path)
    monkeypatch.setattr(drv, "daemon_running", lambda: True)

    drv.swap_and_reload()

    assert [c[1] for c in rndc_spy] == ["reconfig"], "no zone verbs expected"
