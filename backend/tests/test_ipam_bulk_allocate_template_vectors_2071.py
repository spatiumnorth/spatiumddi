"""The server's bulk-allocate names match the console's live preview (#2071).

``frontend/src/lib/bulk-allocate-template.vectors.json`` is read by this test
AND by ``frontend/src/lib/bulk-allocate-template.test.ts``: each vector names
the hostname stored for ``(template, ip, n)``, or null where the template or
that name is refused. Both sides run the same cases, so the dialog cannot
preview one name while the server stores another — the #2071 defect, where
``web{n:_}`` previewed ``web1000`` and stored ``web1_000``.

Skipped rather than failed when the frontend tree is absent: the api image
ships only ``backend/``. CI checks out the whole repo.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.api.v1.ipam.router import (
    _BULK_TEMPLATE_START_MAX,
    BulkAllocateRequest,
    _bulk_stored_hostname,
    _bulk_template_format_error,
    _expand_bulk_template,
)

_VECTORS = (
    Path(__file__).resolve().parents[2]
    / "frontend"
    / "src"
    / "lib"
    / "bulk-allocate-template.vectors.json"
)


def _load() -> dict[str, Any]:
    if not _VECTORS.is_file():
        pytest.skip("frontend/ is outside the api image; run from a checkout")
    data: dict[str, Any] = json.loads(_VECTORS.read_text())
    return data


def _stored(template: str, ip: str, n: int) -> str | None:
    """The endpoint's own sequence: token forms, then render, then host label."""
    if _bulk_template_format_error(template) is not None:
        return None
    rendered = _expand_bulk_template(template, ipaddress.ip_address(ip), n)
    try:
        return _bulk_stored_hostname(rendered)
    except ValueError:
        return None


def test_every_vector_matches_the_server() -> None:
    data = _load()
    assert len(data["vectors"]) > 20
    wrong = [
        (v["template"], v["ip"], v["n"], v["stored"], got)
        for v in data["vectors"]
        if (got := _stored(v["template"], v["ip"], v["n"])) != v["stored"]
    ]
    assert not wrong, wrong


def test_iterator_bounds_match_the_server() -> None:
    data = _load()
    bounds = data["template_start"]
    assert bounds["max"] == _BULK_TEMPLATE_START_MAX
    base = {"range_start": "10.0.0.1", "range_end": "10.0.0.2", "hostname_template": "h{n}"}
    for ok in bounds["accepted"]:
        BulkAllocateRequest(**base, template_start=ok)
    for bad in bounds["refused"]:
        with pytest.raises(ValidationError):
            BulkAllocateRequest(**base, template_start=bad)
