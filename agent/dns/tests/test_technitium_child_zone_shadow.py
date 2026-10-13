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
                "records": [{"name": "www", "type": "A", "value": "192.0.2.99", "ttl": 300}],
            },
        ]
    }


def test_shadowing_zone_picks_the_deepest_descendant() -> None:
    hosted = ["p2.example", "kid.p2.example", "x.kid.p2.example"]
    assert _shadowing_zone("www.kid.p2.example", "p2.example", hosted) == "kid.p2.example"
    assert _shadowing_zone("a.x.kid.p2.example", "p2.example", hosted) == "x.kid.p2.example"
    # The child's apex is the child's too.
    assert _shadowing_zone("kid.p2.example", "p2.example", hosted) == "kid.p2.example"
    assert _shadowing_zone("www.p2.example", "p2.example", hosted) is None
    # A zone never shadows itself or an ancestor, and matching is label-wise.
    assert _shadowing_zone("www.kid.p2.example", "kid.p2.example", hosted) is None
    assert _shadowing_zone("a.mykid.p2.example", "p2.example", hosted) is None


def test_render_leaves_a_shadowed_record_out_of_the_parent(tmp_path: Path) -> None:
    import json

    d = TechnitiumDriver(state_dir=tmp_path)
    d.render(_bundle())
    zones = {z["zone"]: z for z in json.loads((tmp_path / "rendered.new" / "zones.json").read_text())}
    assert [r["domain"] for r in zones["p2.example"]["records"]] == ["www.p2.example"]
    assert [r["domain"] for r in zones["kid.p2.example"]["records"]] == ["www.kid.p2.example"]


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
        {**op, "zone_name": "kid.p2.example.", "record": {**op["record"], "name": "www"}}
    )
    d.apply_record_op({**op, "record": {**op["record"], "name": "www"}})
    assert [c[3]["zone"] for c in calls] == ["kid.p2.example", "p2.example"]
    assert all(c[3]["overwrite"] == "true" for c in calls)
