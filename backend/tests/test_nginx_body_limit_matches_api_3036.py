"""The bundled nginx must not 413 a body the api accepts (#3036).

nginx's 1 MiB default applied to every ``/api/`` route not given its own
location, so imports (25 / 50 MiB) were refused, as an HTML page, before the
api read them. Each route in :data:`app.core.body_limit.ALLOWANCES` must land
in an nginx location whose ``client_max_body_size`` covers the allowance --
checked by resolving a concrete path for each allowance the way nginx picks a
location -- while the generic ``/api/`` location keeps the 1 MiB default and
every raised location streams the body (``proxy_request_buffering off``), so
nginx never spools a large body for a caller the api has not authenticated.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from app.core.body_limit import ALLOWANCES, MIB, Allowance

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CONFS = (
    _ROOT / "frontend" / "default.conf.template",
    _ROOT / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml",
)

pytestmark = pytest.mark.skipif(
    not _CONFS[0].exists(), reason="frontend/ not present in this checkout (dev container)"
)

_NGINX_DEFAULT = MIB

# Allowances nginx never fronts: the slot-image mirror write goes from the api
# straight to the mirror pod's own Service (SLOT_IMAGE_MIRROR_URL, :8000), and
# the route is mounted only there.
_NOT_BEHIND_NGINX = (r"/api/v1/appliance/internal/slot-images/",)

# The api's allowance adds multipart framing headroom (body_limit._FORM_OVERHEAD)
# over the file cap; a dedicated location sized to the file cap itself is fine.
_FORM_OVERHEAD = MIB

_Loc = tuple[str, str, str]


def _to_bytes(v: str) -> int:
    m = re.fullmatch(r"(\d+)([kmg]?)", v.strip().lower())
    assert m, v
    return int(m.group(1)) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[m.group(2)]


def _locations(text: str) -> list[_Loc]:
    """``(modifier, spec, body)`` per ``location`` block, in file order."""
    out = []
    for m in re.finditer(r"^\s*location\s+(?:(=|~\*?|\^~)\s+)?(\S+)\s*\{", text, re.M):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        out.append((m.group(1) or "", m.group(2), text[m.end() : i - 1]))
    return out


def _select(locs: list[_Loc], path: str) -> _Loc:
    """The location nginx serves ``path`` from (exact, longest prefix, regex)."""
    for loc in locs:
        if loc[0] == "=" and loc[1] == path:
            return loc
    prefixes = [loc for loc in locs if loc[0] in ("", "^~") and path.startswith(loc[1])]
    best = max(prefixes, key=lambda loc: len(loc[1])) if prefixes else None
    if best is None or best[0] != "^~":
        for loc in locs:
            if loc[0].startswith("~"):
                flags = re.I if loc[0] == "~*" else 0
                if re.search(loc[1], path, flags):
                    return loc
    assert best is not None, path
    return best


def _limit(body: str) -> int:
    lim = re.search(r"client_max_body_size\s+(\w+);", body)
    return _to_bytes(lim.group(1)) if lim else _NGINX_DEFAULT


def _sample_path(pattern: str) -> str:
    """A concrete request path an allowance's regex fullmatches."""
    p = re.sub(r"\(([^|()]+)\|[^()]*\)", r"\1", pattern)
    p = p.replace("[^/]+", "x").replace(".+", "x")
    assert re.fullmatch(pattern, p), (pattern, p)
    return p


def _fronted() -> list[Allowance]:
    out = [a for a in ALLOWANCES if not a.pattern.pattern.startswith(_NOT_BEHIND_NGINX)]
    assert out
    return out


@pytest.mark.parametrize("conf", _CONFS, ids=lambda p: p.name)
@pytest.mark.parametrize("allowance", _fronted(), ids=lambda a: a.pattern.pattern)
def test_nginx_location_covers_the_api_allowance(conf: pathlib.Path, allowance: Allowance) -> None:
    locs = _locations(conf.read_text())
    path = _sample_path(allowance.pattern.pattern)
    mod, spec, body = _select(locs, path)
    assert _limit(body) >= allowance.max_bytes - _FORM_OVERHEAD, (
        f"{conf.name}: {path} is served by location {mod} {spec}, which admits "
        f"{_limit(body)} bytes, but the api accepts {allowance.max_bytes}; nginx "
        "413s it as HTML before the api reads it"
    )
    assert re.search(r"proxy_request_buffering\s+off;", body), (
        f"{conf.name}: location {mod} {spec} raises the body limit but buffers the "
        "whole body to disk before the api's pre-body auth runs"
    )


@pytest.mark.parametrize("conf", _CONFS, ids=lambda p: p.name)
def test_generic_api_location_keeps_the_default(conf: pathlib.Path) -> None:
    locs = _locations(conf.read_text())
    (generic,) = [loc for loc in locs if loc[:2] == ("", "/api/")]
    assert _limit(generic[2]) <= _NGINX_DEFAULT
    # Ordinary routes still land there, not in a raised location.
    assert _select(locs, "/api/v1/auth/login")[1] == "/api/"
    assert _select(locs, "/api/v1/dns/groups/x/zones/x/records")[1] == "/api/"
    assert _select(locs, "/api/v1/dns/agents/ingested-records/extra")[1] == "/api/"
