"""The bundled nginx must not 413 a body the api accepts (#3036).

nginx's 1 MiB default applied to every ``/api/`` route not given its own
location, so imports (25 / 50 MiB) were refused, as an HTML page, before the
api read them. Each route in :data:`app.core.body_limit.ALLOWANCES` must land
in an nginx location whose ``client_max_body_size`` covers the allowance --
checked by resolving a concrete path for each allowance the way nginx picks a
location -- while the generic ``/api/`` location keeps the 1 MiB default and
every raised location streams the body (``proxy_request_buffering off``), so
nginx never spools a large body for a caller the api has not authenticated.

nginx's limit must not be ABOVE the api's either. Streaming, a body the api
refuses is refused before the api reads it, and the api closes; nginx's next
write then meets the closed socket and the client gets a 502 about one time
in three. So the importer-family locations sit at exactly the allowance, and
answer their own 413 in the api's JSON shape.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from app.core.body_limit import ALLOWANCES, MIB, Allowance, too_large_detail

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
# over the file cap. The backup and upgrade-image locations predate #3036 and
# are sized to the file cap itself, 1 MiB under the allowance: nginx still
# refuses first (at the file cap), so the api never refuses a body nginx
# proxied, and their HTML 413 is unchanged. Every other location must sit at
# exactly the allowance and answer its 413 as the api's JSON.
_FORM_OVERHEAD = MIB
_SIZED_TO_FILE_CAP = (r"/api/v1/backup/", r"/api/v1/appliance/upgrade-images")

_TOO_LARGE_URI = "/_api_body_too_large/"

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
    limit = _limit(body)
    assert limit >= allowance.max_bytes - _FORM_OVERHEAD, (
        f"{conf.name}: {path} is served by location {mod} {spec}, which admits "
        f"{limit} bytes, but the api accepts {allowance.max_bytes}; nginx "
        "413s it as HTML before the api reads it"
    )
    assert limit <= allowance.max_bytes, (
        f"{conf.name}: location {mod} {spec} admits {limit} bytes for {path}, more "
        f"than the api's {allowance.max_bytes}; a body between the two is streamed "
        "to an api that refuses it unread and closes, and the client gets a 502"
    )
    assert re.search(r"proxy_request_buffering\s+off;", body), (
        f"{conf.name}: location {mod} {spec} raises the body limit but buffers the "
        "whole body to disk before the api's pre-body auth runs"
    )
    if allowance.pattern.pattern.startswith(_SIZED_TO_FILE_CAP):
        return
    assert limit == allowance.max_bytes, (
        f"{conf.name}: location {mod} {spec} admits {limit} bytes for {path}; it "
        f"must be the api's exact {allowance.max_bytes}"
    )
    page = re.search(r"error_page\s+413\s+(\S+);", body)
    assert page and page.group(1) == f"{_TOO_LARGE_URI}{allowance.max_bytes}", (
        f"{conf.name}: location {mod} {spec} must answer its 413 through "
        f"{_TOO_LARGE_URI}{allowance.max_bytes}, the api's JSON 413 for that limit, "
        "not nginx's HTML page"
    )


@pytest.mark.parametrize("conf", _CONFS, ids=lambda p: p.name)
@pytest.mark.parametrize("allowance", _fronted(), ids=lambda a: a.pattern.pattern)
def test_nginx_413_is_the_api_json(conf: pathlib.Path, allowance: Allowance) -> None:
    """What ``error_page 413`` lands on renders the api's own 413 body."""
    if allowance.pattern.pattern.startswith(_SIZED_TO_FILE_CAP):
        pytest.skip("nginx's own HTML 413, at the file cap (see _SIZED_TO_FILE_CAP)")
    locs = _locations(conf.read_text())
    uri = f"{_TOO_LARGE_URI}{allowance.max_bytes}"
    mod, spec, body = _select(locs, uri)
    assert re.search(r"^\s*internal;", body, re.M), f"{conf.name}: {spec} must be internal"
    assert re.search(r"default_type\s+application/json;", body), spec
    # A chunked body refused mid-stream reaches this location carrying its
    # length so far; under a limit here it is refused again, as HTML.
    assert re.search(r"client_max_body_size\s+0;", body), (
        f"{conf.name}: {spec} must set client_max_body_size 0, or a chunked "
        "over-limit body gets nginx's HTML 413 instead of this one"
    )
    ret = re.search(r"return\s+(\d+)\s+'(.*)';", body)
    assert ret, f"{conf.name}: {spec} returns nothing"
    capture = re.search(spec, uri)
    assert capture
    rendered = re.sub(r"\$(\d)", lambda m: capture.group(int(m.group(1))), ret.group(2))
    assert int(ret.group(1)) == 413
    assert json.loads(rendered) == {"detail": too_large_detail(allowance.max_bytes)}


@pytest.mark.parametrize("conf", _CONFS, ids=lambda p: p.name)
def test_generic_api_location_keeps_the_default(conf: pathlib.Path) -> None:
    locs = _locations(conf.read_text())
    (generic,) = [loc for loc in locs if loc[:2] == ("", "/api/")]
    assert _limit(generic[2]) <= _NGINX_DEFAULT
    # Ordinary routes still land there, not in a raised location.
    assert _select(locs, "/api/v1/auth/login")[1] == "/api/"
    assert _select(locs, "/api/v1/dns/groups/x/zones/x/records")[1] == "/api/"
    assert _select(locs, "/api/v1/dns/agents/ingested-records/extra")[1] == "/api/"
