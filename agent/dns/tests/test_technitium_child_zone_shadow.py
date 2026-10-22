"""A parent zone's record at a name inside a child zone on the same daemon (#1712).

Technitium files a record under the closest zone it hosts for the name, so the
parent's record would be written into the child, and ``overwrite=true`` there
clears the child's own RRset. The child owns the name: the parent's record is
not written, by the structural render or by a record op.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.technitium import TechnitiumDriver, _shadowing_zone

from .test_technitium_render import _install_fake_request, _seed_token


def _bundle() -> dict[str, Any]:
    return {
        "zones": [
            {
                "name": "p2.example.",
                "type": "primary",
                "records": [
                    {"name": "www.kid", "type": "A", "value": "192.0.2.12", "ttl": 300},
                    {"name": "www", "type": "A", "value": "192.0.2.1", "ttl": 300},
                ],
            },
            {
                "name": "kid.p2.example.",
                "type": "primary",
                "records": [
                    {"name": "www", "type": "A", "value": "192.0.2.99", "ttl": 300}
                ],
            },
        ]
    }


def test_shadowing_zone_picks_the_deepest_descendant() -> None:
    hosted = ["p2.example", "kid.p2.example", "x.kid.p2.example"]
    assert (
        _shadowing_zone("www.kid.p2.example", "p2.example", hosted) == "kid.p2.example"
    )
    assert (
        _shadowing_zone("a.x.kid.p2.example", "p2.example", hosted)
        == "x.kid.p2.example"
    )
    # Not the child's apex: Technitium keeps the parent's side of the cut
    # apart there, which is where a delegation's NS lives.
    assert _shadowing_zone("kid.p2.example", "p2.example", hosted) is None
    assert _shadowing_zone("www.p2.example", "p2.example", hosted) is None
    # A zone never shadows itself or an ancestor, and matching is label-wise.
    assert _shadowing_zone("www.kid.p2.example", "kid.p2.example", hosted) is None
    assert _shadowing_zone("a.mykid.p2.example", "p2.example", hosted) is None


def test_a_child_apex_two_labels_down_is_shadowed() -> None:
    """#2238 — Technitium 15.6.2 refuses a parent's record at the apex of a
    hosted child that is two or more labels below it ("The domain name
    'a.b.p2.test' does not belong to the zone: p2.test"; verified live, and
    15.4.0 accepted it). One label down is still written."""
    hosted = ["p2.example", "kid.p2.example", "a.b.p2.example", "x.kid.p2.example"]
    assert _shadowing_zone("a.b.p2.example", "p2.example", hosted) == "a.b.p2.example"
    assert _shadowing_zone("A.B.P2.example.", "p2.example", hosted) == "a.b.p2.example"
    # From the parent two levels up, the deepest owner wins.
    assert (
        _shadowing_zone("x.kid.p2.example", "p2.example", hosted) == "x.kid.p2.example"
    )
    # One label below its own parent: the cut is still writable there.
    assert _shadowing_zone("x.kid.p2.example", "kid.p2.example", hosted) is None
    assert _shadowing_zone("kid.p2.example", "p2.example", hosted) is None
    # A name two labels down that no hosted zone owns is the parent's own.
    assert _shadowing_zone("c.b.p2.example", "p2.example", hosted) is None


def test_render_leaves_a_shadowed_record_out_of_the_parent(tmp_path: Path) -> None:
    import json

    d = TechnitiumDriver(state_dir=tmp_path)
    d.render(_bundle())
    zones = {
        z["zone"]: z
        for z in json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    }
    assert [r["domain"] for r in zones["p2.example"]["records"]] == ["www.p2.example"]
    assert [r["domain"] for r in zones["kid.p2.example"]["records"]] == [
        "www.kid.p2.example"
    ]


def test_record_op_for_a_shadowed_name_writes_nothing(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    d.render(_bundle())
    (tmp_path / "rendered.new").rename(tmp_path / "rendered")
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})

    op = {
        "zone_name": "p2.example.",
        "op": "create",
        "record": {"name": "www.kid", "type": "A", "value": "192.0.2.12", "ttl": 300},
    }
    d.apply_record_op(op)
    d.apply_record_op({**op, "op": "delete"})
    assert calls == []

    # The child's own record, and the parent's own names, still apply.
    d.apply_record_op(
        {
            **op,
            "zone_name": "kid.p2.example.",
            "record": {**op["record"], "name": "www"},
        }
    )
    d.apply_record_op({**op, "record": {**op["record"], "name": "www"}})
    assert [c[3]["zone"] for c in calls] == ["kid.p2.example", "p2.example"]
    assert all(c[3]["overwrite"] == "true" for c in calls)


def test_the_parents_delegation_at_the_cut_is_still_rendered(tmp_path: Path) -> None:
    """Technitium stores the parent's records at the child's apex on the
    parent's side of the cut, apart from the child's apex, so the delegation
    NS the delegation wizard writes into the parent is not shadowed."""
    import json

    bundle = _bundle()
    bundle["zones"][0]["records"].append(
        {"name": "kid", "type": "NS", "value": "ns1.kid.p2.example.", "ttl": 300}
    )
    d = TechnitiumDriver(state_dir=tmp_path)
    d.render(bundle)
    zones = {
        z["zone"]: z
        for z in json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    }
    assert sorted((r["domain"], r["type"]) for r in zones["p2.example"]["records"]) == [
        ("kid.p2.example", "NS"),
        ("www.p2.example", "A"),
    ]


def test_a_child_zone_the_render_skips_shadows_nothing(tmp_path: Path) -> None:
    """A child the render does not create (a forwarder with no forwarders)
    is not on the daemon, so the parent's record is the only answer there is
    and must be written."""
    import json

    bundle = _bundle()
    bundle["zones"][1] = {
        "name": "kid.p2.example.",
        "type": "forward",
        "forwarders": [],
    }
    d = TechnitiumDriver(state_dir=tmp_path)
    d.render(bundle)
    zones = {
        z["zone"]: z
        for z in json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    }
    assert "kid.p2.example" not in zones
    assert sorted(r["domain"] for r in zones["p2.example"]["records"]) == [
        "www.kid.p2.example",
        "www.p2.example",
    ]


def test_record_op_reads_an_older_agents_snapshot(tmp_path: Path) -> None:
    """A snapshot written before ``hosted_zone_names`` existed still carries
    ``bundle_zone_names``; a record op after the upgrade, before the next
    render, falls back to it rather than to "no child zones"."""
    import json

    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    (tmp_path / "rendered").mkdir()
    (tmp_path / "rendered" / "server.json").write_text(
        json.dumps({"bundle_zone_names": ["kid.p2.example", "p2.example"]})
    )
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d.apply_record_op(
        {
            "zone_name": "p2.example.",
            "op": "create",
            "record": {
                "name": "www.kid",
                "type": "A",
                "value": "192.0.2.12",
                "ttl": 300,
            },
        }
    )
    assert calls == []
