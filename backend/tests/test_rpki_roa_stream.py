"""The streamed, filtered ROA pull (spatiumddi#1054).

The previous service parsed the whole ~100 MB global dump with ``resp.json()``
and cached the million-entry list per process; on the appliance every celery
prefork child that ran one ASN refresh grew by ~380 MB and kept it, and the
worker was OOMKilled on a 6 GB node. These tests pin the replacement: the
incremental parser yields ROA objects one at a time from a streamed body in
any chunking, only the ASNs asked for are indexed and cached, a sweep primes
the cache once, and a failed fetch raises instead of answering empty.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest

from app.services import rpki_roa

pytestmark = pytest.mark.asyncio


def _cloudflare_doc(n_roas: int = 12, *, tail: bool = True) -> dict:
    roas = []
    for i in range(n_roas):
        asn = 13335 if i % 3 == 0 else (15169 if i % 3 == 1 else 64512 + i)
        roas.append(
            {
                "asn": asn,
                "prefix": f"1.{i}.0.0/24",
                "maxLength": 24,
                "ta": "apnic",
                "expires": 1778336254 + i,
            }
        )
    doc = {
        "metadata": {
            "counts": n_roas,
            "generated": 1757900000,
            "valid": 1757910000,
            # A string VALUE that looks exactly like the key we walk for: the
            # parser decodes keys, it does not grep for them.
            "note": 'contains "roas": [ inside a string, and a \\" escaped quote é',
        },
        "roas": roas,
    }
    if tail:
        doc["bgpsec_keys"] = [{"asn": 13335, "ski": "ab" * 20, "pubkey": "x" * 90}]
        doc["nonfunc_cas"] = []
        doc["aspas"] = [{"customer_asid": 64512, "providers": [1, 2, 3]}]
    return doc


async def _chunks(body: bytes, size: int) -> AsyncIterator[bytes]:
    for i in range(0, len(body), size):
        yield body[i : i + size]


async def _collect(body: bytes, size: int) -> list[dict]:
    return [r async for r in rpki_roa.iter_roas(_chunks(body, size))]


@pytest.mark.parametrize("size", [1, 3, 17, 4096, 1 << 20])
async def test_iter_roas_yields_every_entry_in_any_chunking(size: int) -> None:
    doc = _cloudflare_doc(40)
    body = json.dumps(doc).encode()
    out = await _collect(body, size)
    assert out == doc["roas"]


@pytest.mark.parametrize("size", [1, 5, 4096])
async def test_iter_roas_survives_pretty_printing_and_unicode(size: int) -> None:
    doc = _cloudflare_doc(7)
    doc["metadata"]["note"] = 'café — 😀 emoji and "quotes" and }] braces'
    body = json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")
    assert await _collect(body, size) == doc["roas"]


async def test_iter_roas_handles_ripe_envelopes() -> None:
    top = {
        "roas": [
            {
                "asn": "AS15169",
                "prefix": "8.8.8.0/24",
                "maxLength": 24,
                "ta": "arin",
                "notBefore": "2026-01-01T00:00:00Z",
                "notAfter": "2027-01-01T00:00:00Z",
            }
        ]
    }
    assert await _collect(json.dumps(top).encode(), 4) == top["roas"]
    nested = {"data": {"generated": 1, "roas": top["roas"]}, "extra": [1, 2, 3]}
    assert await _collect(json.dumps(nested).encode(), 4) == top["roas"]
    nested_first = {"data": {"roas": top["roas"], "after": {"k": "v"}}, "z": None}
    assert await _collect(json.dumps(nested_first).encode(), 9) == top["roas"]


async def test_iter_roas_stops_at_the_end_of_the_array_and_reads_no_further() -> None:
    doc = _cloudflare_doc(3, tail=False)
    body = json.dumps(doc).encode() + b" garbage that must never be read"
    assert len(await _collect(body, 8)) == 3


async def test_iter_roas_refuses_malformed_truncated_or_roas_less_documents() -> None:
    with pytest.raises(ValueError):
        await _collect(b'{"metadata": {}, "roas": [{"asn": 1, "prefix": ', 4)
    with pytest.raises(ValueError):
        await _collect(b'{"metadata": {"a": 1}}', 4)
    with pytest.raises(ValueError):
        await _collect(b"[1, 2, 3]", 4)
    with pytest.raises(ValueError):
        await _collect(b'{"roas": {"not": "a list"}}', 4)
    with pytest.raises(ValueError):
        await _collect(b"", 4)


async def test_iter_roas_skips_non_object_entries_and_keeps_the_rest() -> None:
    body = b'{"roas": [1, "x", null, {"asn": 5, "prefix": "5.0.0.0/8", "maxLength": 8}]}'
    assert await _collect(body, 3) == [{"asn": 5, "prefix": "5.0.0.0/8", "maxLength": 8}]


# ── The cache and the fetch ─────────────────────────────────────────────


class _Mirror:
    """A fake ``_stream_dump``: counts fetches, serves ``doc`` in 1 KiB chunks
    or fails on demand."""

    def __init__(self, doc: dict | None, *, fail: str | None = None):
        self.body = json.dumps(doc).encode() if doc is not None else b""
        self.fail = fail
        self.fetches = 0

    async def __call__(self, url: str) -> AsyncIterator[bytes]:
        self.fetches += 1
        if self.fail == "transport":
            raise httpx.ConnectError("mirror down")
        if self.fail == "status":
            raise ValueError("http 503")
        async for c in _chunks(self.body, 1024):
            yield c


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch: pytest.MonkeyPatch):
    # The fixtures here are a handful of ROAs, not a full index; the
    # full-index floor has its own tests in test_rpki_roa_failed_fetch_3557.
    monkeypatch.setattr(rpki_roa, "_MIN_INDEX_ENTRIES", 0)
    rpki_roa._clear_cache_for_test()
    yield
    rpki_roa._clear_cache_for_test()


async def test_fetch_roas_for_asn_keeps_only_the_asked_for_asn(monkeypatch) -> None:
    mirror = _Mirror(_cloudflare_doc(30))
    monkeypatch.setattr(rpki_roa, "_stream_dump", mirror)
    out = await rpki_roa.fetch_roas_for_asn(13335, "cloudflare")
    assert len(out) == 10 and all(e["prefix"].startswith("1.") for e in out)
    assert out[0] == {
        "prefix": "1.0.0.0/24",
        "max_length": 24,
        "valid_from": None,
        "valid_to": datetime.fromtimestamp(1778336254, tz=UTC),
        "trust_anchor": "apnic",
    }
    assert mirror.fetches == 1
    # The cache holds the slice, not the dump.
    _, indexed, index = rpki_roa._cache["cloudflare"]
    assert indexed == frozenset({13335}) and set(index) == {13335}
    # A second call for the same AS is a cache hit; a new AS re-primes for the union.
    await rpki_roa.fetch_roas_for_asn(13335, "cloudflare")
    assert mirror.fetches == 1
    out2 = await rpki_roa.fetch_roas_for_asn(15169, "cloudflare")
    assert len(out2) == 10 and mirror.fetches == 2
    assert rpki_roa._cache["cloudflare"][1] == frozenset({13335, 15169})
    # An AS with no ROAs in the dump is an indexed empty answer, not a refetch.
    assert await rpki_roa.fetch_roas_for_asn(64999, "cloudflare") == []
    assert mirror.fetches == 3
    assert await rpki_roa.fetch_roas_for_asn(64999, "cloudflare") == []
    assert mirror.fetches == 3


async def test_prime_roas_makes_one_fetch_for_a_whole_sweep(monkeypatch) -> None:
    mirror = _Mirror(_cloudflare_doc(60))
    monkeypatch.setattr(rpki_roa, "_stream_dump", mirror)
    assert await rpki_roa.prime_roas([13335, 15169, 64514, 64517], "cloudflare") is True
    assert mirror.fetches == 1
    for n in (13335, 15169, 64514, 64517):
        await rpki_roa.fetch_roas_for_asn(n, "cloudflare")
    assert mirror.fetches == 1
    assert len(await rpki_roa.fetch_roas_for_asn(64514, "cloudflare")) == 1
    # Priming a subset of what is already indexed is free.
    assert await rpki_roa.prime_roas([13335], "cloudflare") is True
    assert mirror.fetches == 1


async def test_a_failed_fetch_raises_and_is_never_an_empty_answer(monkeypatch) -> None:
    good = _Mirror(_cloudflare_doc(9))
    monkeypatch.setattr(rpki_roa, "_stream_dump", good)
    assert len(await rpki_roa.fetch_roas_for_asn(13335, "cloudflare")) == 3
    # Expire the cache and make the mirror fail: that is a failure, not "no ROAs".
    fetched_at, indexed, index = rpki_roa._cache["cloudflare"]
    rpki_roa._cache["cloudflare"] = (fetched_at - 10_000, indexed, index)
    bad = _Mirror(None, fail="transport")
    monkeypatch.setattr(rpki_roa, "_stream_dump", bad)
    with pytest.raises(rpki_roa.RoaFetchError):
        await rpki_roa.fetch_roas_for_asn(13335, "cloudflare")
    assert bad.fetches == 1
    assert "transport" in (rpki_roa.last_fetch_error("cloudflare") or "")
    rpki_roa._clear_cache_for_test()
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(None, fail="status"))
    with pytest.raises(rpki_roa.RoaFetchError, match="http 503"):
        await rpki_roa.fetch_roas_for_asn(13335, "cloudflare")
    assert await rpki_roa.prime_roas([1], "cloudflare") is False


async def test_an_asn_the_source_answered_for_with_no_roas_is_an_empty_list(monkeypatch) -> None:
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(_cloudflare_doc(9)))
    assert await rpki_roa.fetch_roas_for_asn(64999, "cloudflare") == []
    assert rpki_roa.last_fetch_error("cloudflare") is None


async def test_unknown_source_raises_without_a_fetch(monkeypatch) -> None:
    mirror = _Mirror(_cloudflare_doc(3))
    monkeypatch.setattr(rpki_roa, "_stream_dump", mirror)
    with pytest.raises(rpki_roa.RoaFetchError):
        await rpki_roa.fetch_roas_for_asn(13335, "nowhere")
    assert mirror.fetches == 0


async def test_ripe_source_uses_the_live_export_endpoint() -> None:
    assert rpki_roa._SOURCE_URLS["ripe"] == "https://rpki-validator.ripe.net/api/export.json"


async def test_ripe_export_shape_parses(monkeypatch) -> None:
    doc = {
        "metadata": {"generated": 1793884163},
        "roas": [
            {"asn": "AS13335", "prefix": "1.0.0.0/24", "maxLength": 24, "ta": "apnic"},
            {"asn": "AS18144", "prefix": "1.0.64.0/18", "maxLength": 18, "ta": "apnic"},
        ],
    }
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(doc))
    out = await rpki_roa.fetch_roas_for_asn(13335, "ripe")
    assert [e["prefix"] for e in out] == ["1.0.0.0/24"]
    assert out[0]["trust_anchor"] == "apnic"


async def test_malformed_rows_are_dropped_and_ripe_windows_are_mapped(monkeypatch) -> None:
    doc = {
        "roas": [
            {
                "asn": "AS15169",
                "prefix": "8.8.8.0/24",
                "maxLength": "24",
                "trustAnchor": "AfriNIC",
                "notBefore": "2026-01-01T00:00:00Z",
                "notAfter": "2027-01-01T00:00:00+00:00",
            },
            {"asn": 15169, "prefix": "", "maxLength": 24},
            {"asn": 15169, "prefix": "8.8.4.0/24"},
            {"customerASN": 15169, "prefix": "9.9.9.0/24", "maxLength": 24, "ta": "ripe"},
            {"asn": True, "prefix": "1.1.1.0/24", "maxLength": 24},
        ]
    }
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(doc))
    out = await rpki_roa.fetch_roas_for_asn(15169, "ripe")
    assert [e["prefix"] for e in out] == ["8.8.8.0/24", "9.9.9.0/24"]
    assert out[0]["trust_anchor"] == "afrinic"
    assert out[0]["valid_from"] == datetime(2026, 1, 1, tzinfo=UTC)
    assert out[0]["valid_to"] == datetime(2027, 1, 1, tzinfo=UTC)
    assert out[1]["trust_anchor"] == "ripe" and out[1]["valid_to"] is None


async def test_the_parse_window_stays_small_over_a_large_array() -> None:
    """The point of the change: walking a big array must not grow the buffer
    with it. 20k entries (~1.6 MB) through 4 KiB chunks — the window is
    trimmed as it goes, so it never holds more than about a chunk plus one
    value."""
    doc = _cloudflare_doc(20_000)
    body = json.dumps(doc).encode()
    seen = 0
    biggest = 0
    orig_trim = rpki_roa._Stream.trim

    def spy(self: rpki_roa._Stream) -> None:
        nonlocal biggest
        biggest = max(biggest, len(self.buf))
        orig_trim(self)

    rpki_roa._Stream.trim = spy  # type: ignore[method-assign]
    try:
        async for _ in rpki_roa.iter_roas(_chunks(body, 4096)):
            seen += 1
    finally:
        rpki_roa._Stream.trim = orig_trim  # type: ignore[method-assign]
    assert seen == 20_000
    assert biggest < rpki_roa._TRIM_AT + 4096 * 2
