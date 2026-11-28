"""Option 82 (relay agent information) match: spec rules and the Kea compiler (#54).

Pure, no database. The guarantee under test is structural: every operator
value reaches the Kea test as a number the compiler formats or as hex it
derives from bytes, so no quote, backslash or control character can come out
of it. Kea string literals have no escape for ``'`` (measured on kea-dhcp4
3.0.3), so a quoted literal could not be made safe; hex is.
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.drivers.dhcp.kea import KeaDriver
from app.drivers.dhcp.registry import get_driver
from app.services.dhcp.relay_match import parse_spec, spec_warnings

GOLDEN = Path(__file__).parent / "fixtures" / "relay_match_golden.json"
# Everything a compiled test may contain: no quote, backslash or control char.
ALLOWED = re.compile(r"^[a-z0-9A-F\[\]()., =\-]+$")


def _spec(*conds: dict, combine: str = "all") -> dict:
    return {"kind": "relay_agent", "combine": combine, "conditions": list(conds)}


def _compile(raw: dict) -> str:
    return KeaDriver().compile_relay_match(parse_spec(raw).to_def())


def _one(**cond: object) -> str:
    return _compile(_spec(cond))


# ── Each operator ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("cond", "expected"),
    [
        ({"sub_option": 1, "op": "exists"}, "(relay4[1].exists)"),
        ({"sub_option": 9, "op": "not_exists"}, "(not relay4[9].exists)"),
        (
            {"sub_option": 1, "op": "equals", "encoding": "hex", "value": "0A0B"},
            "(relay4[1].hex == 0x0A0B)",
        ),
        (
            {"sub_option": 2, "op": "not_equals", "encoding": "hex", "value": "AABB"},
            "((relay4[2].exists and not (relay4[2].hex == 0xAABB)))",
        ),
        (
            {"sub_option": 2, "op": "starts_with", "encoding": "hex", "value": "AABBCC"},
            "(substring(relay4[2].hex, 0, 3) == 0xAABBCC)",
        ),
        (
            {"sub_option": 1, "op": "ends_with", "encoding": "hex", "value": "0A0B0C"},
            "(substring(relay4[1].hex, -3, all) == 0x0A0B0C)",
        ),
        (
            {"sub_option": 1, "op": "slice", "offset": 2, "encoding": "hex", "value": "0064"},
            "(substring(relay4[1].hex, 2, 2) == 0x0064)",
        ),
    ],
)
def test_each_operator_compiles_to_its_kea_term(cond: dict, expected: str) -> None:
    assert _compile(_spec(cond)) == expected


def test_text_is_compiled_as_the_hex_of_its_utf8_bytes() -> None:
    assert _one(sub_option=1, op="equals", value="eth0/1:100") == (
        "(relay4[1].hex == 0x657468302F313A313030)"
    )
    assert _one(sub_option=1, op="equals", value="é") == "(relay4[1].hex == 0xC3A9)"


def test_all_and_any_join_the_terms_in_the_operators_order() -> None:
    a = {"sub_option": 2, "op": "exists"}
    b = {"sub_option": 1, "op": "exists"}
    assert _compile(_spec(a, b)) == "(relay4[2].exists) and (relay4[1].exists)"
    assert _compile(_spec(a, b, combine="any")) == "(relay4[2].exists) or (relay4[1].exists)"


@pytest.mark.parametrize(
    "typed", ["aabbcc", "0xAABBCC", "0XaaBBcc", "AA:BB:CC", "aa-bb-cc", "aa.bb.cc", " AA BB CC "]
)
def test_hex_is_normalised(typed: str) -> None:
    cond = parse_spec(
        _spec({"sub_option": 1, "op": "equals", "encoding": "hex", "value": typed})
    ).conditions[0]
    assert cond.value == "AABBCC"


def test_normalising_twice_changes_nothing() -> None:
    """A stored spec posted back by the UI must be a no-op."""
    first = parse_spec(
        _spec({"sub_option": 1, "op": "equals", "encoding": "hex", "value": "aa:bb"})
    ).stored()
    assert parse_spec(first).stored() == first
    text = parse_spec(_spec({"sub_option": 1, "op": "equals", "value": "Gi1/0/7"})).stored()
    assert parse_spec(text).stored() == text


# ── Refusals ─────────────────────────────────────────────────────────────────


def _bad(*conds: dict, **spec: object) -> None:
    raw = {"conditions": list(conds), **spec}
    with pytest.raises(ValidationError):
        parse_spec(raw)


@pytest.mark.parametrize(
    "cond",
    [
        {"sub_option": 1, "op": "equals", "value": ""},
        {"sub_option": 1, "op": "equals", "encoding": "hex", "value": ""},
        {"sub_option": 1, "op": "equals", "encoding": "hex", "value": "0x"},
        {"sub_option": 1, "op": "equals", "encoding": "hex", "value": "ABC"},
        {"sub_option": 1, "op": "equals", "encoding": "hex", "value": "ZZ"},
        {"sub_option": 1, "op": "equals", "encoding": "hex", "value": "AA'BB"},
        {"sub_option": 1, "op": "equals", "value": "x" * 256},
        {"sub_option": 1, "op": "equals", "encoding": "hex", "value": "AA" * 256},
        {"sub_option": 1, "op": "equals", "value": "�"},
        {"sub_option": 1, "op": "equals", "value": "\ud800"},
        {"sub_option": 1, "op": "equals", "value": "a\x00b"},  # JSONB cannot store U+0000
        {"sub_option": 0, "op": "exists"},
        {"sub_option": 256, "op": "exists"},
        {"sub_option": -1, "op": "exists"},
        {"sub_option": True, "op": "exists"},
        {"sub_option": "1", "op": "exists"},
        {"sub_option": 1.0, "op": "exists"},
        {"sub_option": 1, "op": "exists", "value": "AA"},
        {"sub_option": 1, "op": "not_exists", "offset": 0},
        {"sub_option": 1, "op": "equals"},
        {"sub_option": 1, "op": "equals", "value": "a", "offset": 1},
        {"sub_option": 1, "op": "slice", "value": "a"},
        {"sub_option": 1, "op": "slice", "offset": 255, "value": "a"},
        {"sub_option": 1, "op": "slice", "offset": -1, "value": "a"},
        {"sub_option": 1, "op": "slice", "offset": True, "value": "a"},
        {"sub_option": 1, "op": "regex", "value": "a"},
        {"sub_option": 1, "op": "exists", "unknown": 1},
        {"sub_option": 1, "op": "equals", "value": "a", "encoding": "base64"},
        {"op": "exists"},
    ],
)
def test_a_bad_condition_is_refused(cond: dict) -> None:
    _bad(cond)


def test_spec_level_refusals() -> None:
    ok = {"sub_option": 1, "op": "exists"}
    _bad()  # no conditions
    _bad(*[ok] * 17)  # one over the limit
    parse_spec(_spec(*[ok] * 16))
    _bad(ok, combine="some")
    _bad(ok, kind="relay6")
    _bad(ok, surprise=True)


def test_a_driver_that_cannot_render_refuses_instead_of_matching_everything() -> None:
    spec = parse_spec(_spec({"sub_option": 1, "op": "exists"})).to_def()
    with pytest.raises(NotImplementedError):
        get_driver("windows_dhcp").compile_relay_match(spec)
    with pytest.raises(NotImplementedError):
        get_driver("fortigate").compile_relay_match(spec)
    assert get_driver("fortigate").relay_match_support(spec)[0] is False


# ── Hostile values ───────────────────────────────────────────────────────────

HOSTILE = [
    "' or 1 --",
    "'",
    "''",
    '"',
    "\\",
    "\\x27",
    "line1\nline2",
    "\r\n",
    "\t",
    " ",
    "emoji \U0001f600",
    "') or (relay4[1].exists",
    "0xdeadbeef",
    '}, {"Dhcp4": 1}',
    "not (relay4[1].exists)) or (1 == 1",
    "$(rm -rf /)",
    "%s%d",
    "\u0001\u001f\u007f",
]


@pytest.mark.parametrize("value", HOSTILE)
@pytest.mark.parametrize("op", ["equals", "not_equals", "starts_with", "ends_with"])
def test_hostile_text_compiles_to_hex_and_nothing_else(value: str, op: str) -> None:
    out = _one(sub_option=1, op=op, value=value)
    assert ALLOWED.match(out), out
    assert "'" not in out and '"' not in out and "\\" not in out
    # The only literal is the hex of exactly the bytes the operator typed.
    assert f"0x{value.encode().hex().upper()}" in out
    assert out.count("0x") == 1
    json.dumps({"test": out})  # cannot break the Kea JSON the agent renders
    assert json.loads(json.dumps({"test": out}))["test"] == out


def test_a_nul_byte_is_reachable_as_hex() -> None:
    out = _one(sub_option=1, op="equals", encoding="hex", value="61:00:62")
    assert out == "(relay4[1].hex == 0x610062)"


def test_slice_with_hostile_text_stays_in_the_alphabet() -> None:
    out = _one(sub_option=1, op="slice", offset=7, value="'; drop")
    assert ALLOWED.match(out), out


def test_a_randomised_sweep_never_leaves_the_alphabet() -> None:
    rng = random.Random(54)
    alphabet = "'\"\\\n\r\x00 ;()[]{}=,.-0123456789abcdefxXAé�\U0001f600"
    ops = ["exists", "not_exists", "equals", "not_equals", "starts_with", "ends_with", "slice"]
    accepted = 0
    for _ in range(3000):
        conds = []
        for _ in range(rng.randint(1, 4)):
            op = rng.choice(ops)
            c: dict = {"sub_option": rng.randint(1, 255), "op": op}
            if op not in ("exists", "not_exists"):
                c["encoding"] = rng.choice(["text", "hex"])
                c["value"] = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
            if op == "slice":
                c["offset"] = rng.randint(0, 254)
            conds.append(c)
        try:
            spec = parse_spec(_spec(*conds, combine=rng.choice(["all", "any"])))
        except ValidationError:
            continue
        accepted += 1
        out = KeaDriver().compile_relay_match(spec.to_def())
        assert ALLOWED.match(out), (conds, out)
    assert accepted > 300  # the sweep exercised the compiler, not only the refusals


# ── Warnings ─────────────────────────────────────────────────────────────────


def test_warnings() -> None:
    neg = parse_spec(_spec({"sub_option": 1, "op": "not_equals", "value": "x"}))
    assert any("not equals" in w for w in spec_warnings(neg))
    none = parse_spec(_spec({"sub_option": 1, "op": "not_exists"}))
    assert any("every client that is not behind a relay" in w for w in spec_warnings(none))
    ok = parse_spec(_spec({"sub_option": 1, "op": "equals", "value": "eth0"}))
    assert spec_warnings(ok) == []
    binary = parse_spec(_spec({"sub_option": 1, "op": "equals", "value": "é"}))
    assert any("printable ASCII" in w for w in spec_warnings(binary))


def test_windows_support_mapping() -> None:
    win = get_driver("windows_dhcp")

    def sup(*conds: dict) -> tuple[bool, str]:
        return win.relay_match_support(parse_spec(_spec(*conds)).to_def())

    assert sup({"sub_option": 1, "op": "starts_with", "value": "a"})[0] is True
    assert sup({"sub_option": 12, "op": "equals", "value": "a"})[0] is False
    assert sup({"sub_option": 1, "op": "exists"})[0] is False
    assert sup({"sub_option": 1, "op": "slice", "offset": 1, "value": "a"})[0] is False


# ── Golden fixture ───────────────────────────────────────────────────────────


def test_the_compiler_reproduces_the_golden_fixture() -> None:
    """``relay_match_golden.json`` is also what ``kea-dhcp4 -t`` is run over
    (``agent/dhcp/tests/test_relay_match_kea_live.py``), so a change to the
    compiler has to change the file the real Kea parses."""
    cases = json.loads(GOLDEN.read_text())
    assert len(cases) >= 20
    for case in cases:
        assert _compile(case["spec"]) == case["expression"], case["spec"]
