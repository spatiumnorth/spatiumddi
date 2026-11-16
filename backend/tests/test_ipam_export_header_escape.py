"""The IPAM export escapes header cells (custom-field keys) like value cells.

Pure serialiser / parser tests: no database.
"""

from __future__ import annotations

import csv
import io

import pytest
from openpyxl import load_workbook

from app.services.ipam_io.export import ExportBundle, _to_csv, _to_xlsx
from app.services.ipam_io.parser import parse_csv, parse_xlsx

KEYS = ["=x", "+y", "@z", "-w", "\tt", "\rr", "plain"]


def _bundle(include_addresses: bool) -> ExportBundle:
    cf = {k: "v" for k in KEYS}
    return ExportBundle(
        space=None,
        blocks=[],
        subnets=[{"network": "10.0.0.0/24", "name": "n", "custom_fields": dict(cf)}],
        addresses=[{"subnet": "10.0.0.0/24", "address": "10.0.0.5", "custom_fields": dict(cf)}],
        include_addresses=include_addresses,
    )


def _csv_header(data: bytes) -> list[str]:
    return next(csv.reader(io.StringIO(data.decode(), newline="")))


@pytest.mark.parametrize("addresses", [False, True])
def test_csv_header_escaped(addresses: bool) -> None:
    header = _csv_header(_to_csv(_bundle(addresses)))
    for k in KEYS[:-1]:
        assert "'" + k in header
        assert k not in header
    assert "plain" in header


def test_xlsx_headers_escaped_on_both_sheets() -> None:
    wb = load_workbook(io.BytesIO(_to_xlsx(_bundle(True))))
    for sheet in ("subnets", "addresses"):
        header = [c.value for c in wb[sheet][1]]
        for k in KEYS[:-1]:
            assert "'" + k in header
            assert k not in header
        assert "plain" in header


@pytest.mark.parametrize("addresses", [False, True])
def test_csv_round_trip_keeps_keys(addresses: bool) -> None:
    parsed = parse_csv(_to_csv(_bundle(addresses)))
    rows = parsed.addresses if addresses else parsed.subnets
    assert set(rows[0]["custom_fields"]) == set(KEYS)


def test_xlsx_round_trip_keeps_keys() -> None:
    parsed = parse_xlsx(_to_xlsx(_bundle(True)))
    assert set(parsed.subnets[0]["custom_fields"]) == set(KEYS)
    assert set(parsed.addresses[0]["custom_fields"]) == set(KEYS)


def test_apostrophe_key_unchanged() -> None:
    b = _bundle(False)
    b.subnets[0]["custom_fields"] = {"'plain": "v"}
    assert "'plain" in _csv_header(_to_csv(b))
    assert set(parse_csv(_to_csv(b)).subnets[0]["custom_fields"]) == {"'plain"}


VALUES = ["=1+1", "+y", "@z", "-w", "\tt", "\rr", "plain"]


def _value_bundle() -> ExportBundle:
    cf = {f"k{i}": v for i, v in enumerate(VALUES)}
    return ExportBundle(
        space=None,
        blocks=[],
        subnets=[{"network": "10.0.0.0/24", "name": "=n", "custom_fields": dict(cf)}],
        addresses=[
            {
                "subnet": "10.0.0.0/24",
                "address": "10.0.0.5",
                "hostname": "@h",
                "description": "-d",
                "custom_fields": dict(cf),
            }
        ],
        include_addresses=False,
    )


def test_csv_round_trip_keeps_values() -> None:
    b = _value_bundle()
    sub = parse_csv(_to_csv(b)).subnets[0]
    assert sub["name"] == "=n"
    assert list(sub["custom_fields"].values()) == VALUES
    b.include_addresses = True
    addr = parse_csv(_to_csv(b)).addresses[0]
    assert addr["hostname"] == "@h" and addr["description"] == "-d"
    assert list(addr["custom_fields"].values()) == VALUES


def test_xlsx_round_trip_keeps_values() -> None:
    parsed = parse_xlsx(_to_xlsx(_value_bundle()))
    assert parsed.subnets[0]["name"] == "=n"
    assert list(parsed.subnets[0]["custom_fields"].values()) == VALUES
    assert parsed.addresses[0]["hostname"] == "@h"
    assert list(parsed.addresses[0]["custom_fields"].values()) == VALUES
