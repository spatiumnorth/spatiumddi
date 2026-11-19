"""The streamed bundle parse must agree with ``json.loads`` exactly (#2223).

``parse_bundle_file`` decodes a bundle a top-level array element at a time
over a chunked text stream. A wrong answer there is not a wrong zone, it is
every zone: the cached bundle is what the agent serves from when the control
plane is away (non-negotiable #5). So equivalence is checked, not assumed:

* a seeded fuzz corpus (escapes, ``\\u`` escapes, surrogate pairs, raw
  multi-byte text, every number shape, nesting, empty containers, whitespace),
  parsed at many chunk sizes so every token lands on a buffer boundary;
* the real 256 KiB chunk, with each awkward token placed exactly across it;
* single elements several MiB long (an RPZ feed's blocklist);
* truncated and mutated documents, which must fail when ``json.loads`` fails
  and never come back as a partial bundle.

Comparison is by re-serialisation, not ``==``: that also tells ``1`` from
``1.0`` and ``True`` from ``1``, and treats ``NaN`` as equal to itself.

Seeded ``random`` rather than Hypothesis, which the agent's test deps do not
carry; the seeds are fixed, so a failure reproduces.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent import cache as cache_mod
from spatium_dns_agent.cache import parse_bundle_file

# Characters that stress the text layer: an escape, a quote, a backslash,
# two-, three- and four-byte UTF-8 (the last a surrogate pair in ``\\u`` form),
# control characters and a lone surrogate ``json`` accepts as an escape.
_ALPHABET = [
    "a",
    "Z",
    "0",
    " ",
    '"',
    "\\",
    "/",
    "\b",
    "\f",
    "\n",
    "\r",
    "\t",
    "\x00",
    "\x1f",
    "é",
    "ß",
    "€",
    "中",
    "😀",
    "𝄞",
    " ",
    "﻿",
]

# Number spellings ``json.dumps`` never writes but a document may carry.
_RAW_NUMBERS = [
    "0",
    "-0",
    "-0.0",
    "1.5",
    "1e5",
    "1E5",
    "1e+5",
    "1E-5",
    "-2.5e-10",
    "123456789012345678901234567890",
    "0.000001",
    "6.02214076e23",
    "1.7976931348623157e308",
    "5e-324",
]


def _scalar(rng: random.Random) -> Any:
    pick = rng.randrange(8)
    if pick == 0:
        return None
    if pick == 1:
        return rng.random() < 0.5
    if pick == 2:
        return rng.randint(-(10**20), 10**20)
    if pick == 3:
        return rng.uniform(-1e6, 1e6) * 10 ** rng.randint(-30, 30)
    if pick == 4:
        return float(rng.choice(_RAW_NUMBERS))
    if pick == 5 and rng.random() < 0.2:
        return rng.choice([float("nan"), float("inf"), float("-inf")])
    return "".join(rng.choice(_ALPHABET) for _ in range(rng.randrange(0, 24)))


def _value(rng: random.Random, depth: int) -> Any:
    if depth <= 0 or rng.random() < 0.45:
        return _scalar(rng)
    if rng.random() < 0.5:
        return [_value(rng, depth - 1) for _ in range(rng.randrange(0, 5))]
    return {_key(rng): _value(rng, depth - 1) for _ in range(rng.randrange(0, 5))}


def _key(rng: random.Random) -> str:
    if rng.random() < 0.6:
        return rng.choice(["name", "records", "type", "ttl", "value", "", "é", 'q"k'])
    return "".join(rng.choice(_ALPHABET) for _ in range(rng.randrange(0, 8)))


def _bundle(rng: random.Random) -> dict[str, Any]:
    """An object whose members are a mix of arrays (decoded element-wise,
    each element any value, bare numbers included) and plain values."""
    doc: dict[str, Any] = {}
    for _ in range(rng.randrange(0, 6)):
        key = rng.choice(["zones", "blocklists", "acls", "etag", "ttl", "x", ""])
        if rng.random() < 0.6:
            doc[key] = [_value(rng, 4) for _ in range(rng.randrange(0, 6))]
        else:
            doc[key] = _value(rng, 3)
    return doc


def _raw(value: Any, rng: random.Random) -> str:
    """``value`` as JSON text with random whitespace, ``\\u`` escapes and the
    number spellings ``json.dumps`` does not produce."""

    def ws() -> str:
        return "".join(rng.choice(" \t\n\r") for _ in range(rng.choice([0, 0, 0, 1, 3])))

    if isinstance(value, dict):
        body = ",".join(
            f"{ws()}{_raw(k, rng)}{ws()}:{ws()}{_raw(v, rng)}{ws()}" for k, v in value.items()
        )
        return "{" + (body or ws()) + "}"
    if isinstance(value, list):
        body = ",".join(f"{ws()}{_raw(v, rng)}{ws()}" for v in value)
        return "[" + (body or ws()) + "]"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=rng.random() < 0.5)
    if value.__class__ is float and rng.random() < 0.3:
        # ``repr`` exponent forms ("1e-05") and an upper-case "E".
        text = repr(value)
        return text.upper() if "e" in text and rng.random() < 0.5 else text
    return json.dumps(value)


def _canon(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True)


def _assert_same(path: Path) -> None:
    """``parse_bundle_file`` agrees with ``json.loads``: the same value, or a
    ``ValueError`` from both."""
    data = path.read_bytes()
    try:
        expected = json.loads(data)
    except ValueError:
        with pytest.raises(ValueError):
            parse_bundle_file(path)
        return
    assert _canon(parse_bundle_file(path)) == _canon(expected)
    if isinstance(expected, dict):
        # ``records=False`` is the same parse less each element's record level.
        for key, member in (("zones", "records"), ("blocklists", "entries")):
            if isinstance(expected.get(key), list):
                for item in expected[key]:
                    if isinstance(item, dict):
                        item.pop(member, None)
        assert _canon(parse_bundle_file(path, records=False)) == _canon(expected)


@pytest.mark.parametrize("seed", range(40))
def test_fuzzed_bundles_parse_as_json_loads_at_every_chunk_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seed: int
) -> None:
    rng = random.Random(seed)
    path = tmp_path / "b.json"
    for _ in range(6):
        doc = _bundle(rng)
        renderings = [
            json.dumps(doc),
            json.dumps(doc, ensure_ascii=False, separators=(",", ":")),
            json.dumps(doc, indent="\t"),
            _raw(doc, rng),
        ]
        for text in renderings:
            encoding = rng.choice(["utf-8", "utf-8", "utf-8-sig", "utf-16", "utf-32"])
            path.write_bytes(text.encode(encoding, "surrogatepass"))
            # Every boundary in a short document, a sample in a long one.
            sizes = set(range(1, 12)) | {rng.randrange(1, max(2, len(text))) for _ in range(6)}
            for chunk in sorted(sizes):
                monkeypatch.setattr(cache_mod, "_PARSE_CHUNK", chunk)
                _assert_same(path)


@pytest.mark.parametrize(
    "token",
    [
        '"\\""',  # an escaped quote
        '"\\\\"',  # an escaped backslash
        '"\\u00e9"',
        '"\\ud83d\\ude00"',  # a surrogate pair, split between its halves too
        '"é"',
        '"€"',
        '"😀"',
        "1.5e-7",
        "-0.0",
        "1E+300",
        "12345678901234567890",
        "true",
        "null",
        "[]",
        "{}",
    ],
)
@pytest.mark.parametrize("where", ["element", "member"])
def test_a_token_split_across_the_real_chunk_boundary(
    tmp_path: Path, token: str, where: str
) -> None:
    """At the shipped 256 KiB chunk: the token is placed at every offset that
    puts the boundary inside it, before it and after it."""
    chunk = cache_mod._PARSE_CHUNK
    path = tmp_path / "b.json"
    for shift in range(-3, len(token) + 3):
        # The prefix is padding whose length puts ``token`` at chunk - shift.
        head = '{"pad":"' if where == "member" else '{"zones":["'
        pad = "x" * (chunk - shift - len(head) - len('","t":' if where == "member" else '",'))
        if where == "member":
            text = f'{head}{pad}","t":{token},"zones":[{token},{token}]}}'
        else:
            text = f'{head}{pad}",{token},{token}],"t":{token}}}'
        for encoding in ("utf-8", "utf-16"):
            path.write_bytes(text.encode(encoding, "surrogatepass"))
            _assert_same(path)


def test_a_multibyte_character_split_at_the_byte_and_character_boundary(tmp_path: Path) -> None:
    """The text layer, not the parse, reads bytes: a four-byte character that
    straddles a raw read, at every byte offset around the chunk."""
    chunk = cache_mod._PARSE_CHUNK
    path = tmp_path / "b.json"
    for shift in range(12):
        text = '{"zones":["' + "é" * (chunk // 2 - shift) + "😀€中" * 4 + '"]}'
        path.write_text(text, encoding="utf-8")
        _assert_same(path)


@pytest.mark.parametrize("mib", [1, 3, 7])
def test_one_element_several_mib_long(tmp_path: Path, mib: int) -> None:
    """A single zone or blocklist larger than the chunk many times over (an
    RPZ feed), with neighbours either side so the buffer state carries over."""
    entries = []
    size = 0
    i = 0
    while size < mib << 20:
        entry = {"domain": f"d{i}.blocked.test", "action": "block", "note": 'é😀"\\'}
        size += 60
        entries.append(entry)
        i += 1
    doc = {
        "blocklists": [{"name": "small", "entries": []}, {"name": "rpz", "entries": entries}, 7.5],
        "zones": [{"name": "a.test.", "records": [{"ttl": 1.0}]}],
        "ttl": 1e-3,
    }
    path = tmp_path / "b.json"
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    _assert_same(path)
    slim = parse_bundle_file(path, records=False)
    assert [b.get("entries") for b in slim["blocklists"][:2]] == [None, None]
    assert slim["zones"] == [{"name": "a.test."}]


@pytest.mark.parametrize("seed", range(8))
def test_a_truncated_bundle_is_refused_never_returned_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seed: int
) -> None:
    """Every proper prefix of an object document is invalid JSON, so every one
    must raise — a cache cut short by a crash is no cache."""
    rng = random.Random(1000 + seed)
    doc = {"zones": [_value(rng, 3) for _ in range(5)], "etag": "x", "n": 1.25}
    text = json.dumps(doc, ensure_ascii=False)
    data = text.encode("utf-8")
    path = tmp_path / "b.json"
    monkeypatch.setattr(cache_mod, "_PARSE_CHUNK", rng.choice([1, 3, 16]))
    for cut in range(len(data)):
        path.write_bytes(data[:cut])
        with pytest.raises(ValueError):
            parse_bundle_file(path)


@pytest.mark.parametrize("seed", range(8))
def test_a_mutated_bundle_fails_exactly_when_json_loads_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seed: int
) -> None:
    rng = random.Random(2000 + seed)
    path = tmp_path / "b.json"
    for _ in range(150):
        doc = _bundle(rng)
        data = bytearray(json.dumps(doc, ensure_ascii=rng.random() < 0.5).encode())
        for _ in range(rng.randrange(1, 4)):
            if not data:
                break
            pos = rng.randrange(len(data))
            op = rng.randrange(3)
            if op == 0:
                data[pos] = rng.choice(b'{}[],:"\\0123456789.eE+-tfn x\xc3\xa9\xff')
            elif op == 1:
                del data[pos]
            else:
                data.insert(pos, rng.choice(b'{}[],:" \\.e-'))
        path.write_bytes(bytes(data))
        monkeypatch.setattr(cache_mod, "_PARSE_CHUNK", rng.choice([1, 2, 5, 64, 1 << 18]))
        _assert_same(path)


def test_parsed_containers_are_never_shared_between_elements(tmp_path: Path) -> None:
    """The memo shares strings only: equal lists and objects in different
    zones are distinct objects, so mutating one cannot change another."""
    zone = {"name": "a", "forwarders": [], "masters": ["10.0.0.1"], "opts": {"k": "v"}}
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"zones": [zone, zone, zone], "acls": [[], []]}))
    bundle = parse_bundle_file(path)
    a, b, _c = bundle["zones"]
    for key in ("forwarders", "masters", "opts"):
        assert a[key] == b[key] and a[key] is not b[key]
    assert bundle["acls"][0] is not bundle["acls"][1]
    a["forwarders"].append("x")
    a["opts"]["k"] = "changed"
    assert b["forwarders"] == [] and b["opts"] == {"k": "v"}
    assert bundle["zones"][2]["forwarders"] == []


def test_one_huge_element_is_not_held_whole_as_text(tmp_path: Path) -> None:
    """A catalogue blocklist is ONE element of ``blocklists``. Buffering it
    whole to decode it (and doubling the buffer to get there) cost more than
    the read-it-all parse it replaced — found validating #2223 at 1.4M entries:
    641 MB peak against 512 MB. Too big for the buffer, it is decoded an entry
    at a time instead, so the text in memory stays near one chunk."""
    import gc
    import tracemalloc

    entries = [
        {"domain": f"d{i}.blocked.example", "action": "block", "is_wildcard": True}
        for i in range(60_000)
    ]
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"blocklists": [{"name": "rpz", "entries": entries}]}))
    size = path.stat().st_size
    assert size > 4 * cache_mod._PARSE_CHUNK
    del entries
    gc.collect()
    tracemalloc.start()
    try:
        bundle = parse_bundle_file(path)
        held, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert _canon(bundle) == _canon(json.loads(path.read_bytes()))
    # The objects plus a chunk or two of text; the whole element's text on top
    # (the defect) is ``size`` more again, twice over while the buffer grows.
    assert peak - held < size / 2, f"peak {(peak - held) / 1e6:.1f} MB over {size / 1e6:.1f} MB"
