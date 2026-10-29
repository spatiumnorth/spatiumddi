"""The bundled nginx must not 413 a body the api accepts (#3036).

nginx's 1 MiB default applied to every ``/api/`` route not given its own
location, so imports (25 / 50 MiB) were refused before the api read them.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from app.core.body_limit import ALLOWANCES, GIB

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CONFS = (
    _ROOT / "frontend" / "default.conf.template",
    _ROOT / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml",
)

pytestmark = pytest.mark.skipif(
    not _CONFS[0].exists(), reason="frontend/ not present in this checkout (dev container)"
)

# Routes with a dedicated nginx location (sized there, not on /api/).
_OWN_LOCATION = (r"/api/v1/backup/", r"/api/v1/appliance/upgrade-images")


def _to_bytes(v: str) -> int:
    m = re.fullmatch(r"(\d+)([kmg]?)", v.strip().lower())
    assert m, v
    return int(m.group(1)) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[m.group(2)]


def _location_limit(text: str, prefix: str) -> int:
    m = re.search(r"location " + re.escape(prefix) + r" \{(.*?)\n\s*\}", text, re.S)
    assert m, f"no location {prefix}"
    lim = re.search(r"client_max_body_size\s+(\w+);", m.group(1))
    return _to_bytes(lim.group(1)) if lim else 1024**2  # nginx default 1m


@pytest.mark.parametrize("conf", _CONFS, ids=lambda p: p.name)
def test_generic_api_location_covers_every_import_route(conf: pathlib.Path) -> None:
    text = conf.read_text()
    generic = _location_limit(text, "/api/")
    needed = [
        a
        for a in ALLOWANCES
        if a.max_bytes < GIB and not any(a.pattern.pattern.startswith(p) for p in _OWN_LOCATION)
    ]
    assert needed
    for a in needed:
        assert generic >= a.max_bytes, (
            f"{conf.name}: location /api/ allows {generic} bytes but "
            f"{a.pattern.pattern} accepts {a.max_bytes}"
        )


@pytest.mark.parametrize("conf", _CONFS, ids=lambda p: p.name)
def test_dedicated_locations_cover_their_allowances(conf: pathlib.Path) -> None:
    text = conf.read_text()
    for prefix in _OWN_LOCATION:
        need = max(a.max_bytes for a in ALLOWANCES if a.pattern.pattern.startswith(prefix))
        # The api's allowance adds multipart framing headroom on top of the
        # payload cap; nginx's limit only has to cover the payload (2 GiB / 4 GiB).
        assert _location_limit(text, prefix) >= need - 1024**2
