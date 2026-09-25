"""The storage action route keeps its own answer through the frontend (#1080).

``POST /api/v1/appliance/appliances/{id}/storage/action`` waits up to 90 s for
the appliance's supervisor and answers ``504 "<hostname> did not answer the
storage action in time"``; the supervisor waits 60 s for the host runner and
answers ``ok=false "the host storage runner did not answer within 60s"`` -- a
report that reaches the api a little AFTER a 60 s proxy clock that started
before the supervisor's. With the generic ``location /api/`` budget of 60 s,
nginx answered for the api at 60.000 s every time and neither message reached
the operator (observed live on the QA fleet, 2026-09-13 and 2026-09-21). The
route now has its own location in both hand-maintained nginx configs, sized
above the route's budget.

These read the two configs and the two product budgets from source, so the
three numbers cannot drift apart unnoticed: proxy > route > supervisor.

    python3 -m pytest appliance/tests/test_frontend_storage_action_budget.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
IMAGE_TEMPLATE = REPO / "frontend" / "default.conf.template"
APPLIANCE_TEMPLATE = REPO / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml"
ROUTE_SOURCE = REPO / "backend" / "app" / "api" / "v1" / "appliance" / "supervisor.py"
SUPERVISOR_SOURCE = REPO / "agent" / "supervisor" / "spatium_supervisor" / "storage_proxy.py"

CONFIGS = pytest.mark.parametrize(
    "path", [IMAGE_TEMPLATE, APPLIANCE_TEMPLATE], ids=["image-template", "appliance-tls-configmap"]
)

#: The route's location must be a regex on the exact path, any appliance id, so
#: no other route under /api/ inherits the longer wait.
STORAGE_ACTION_SPEC = re.compile(r"^~\s*\^/api/v1/appliance/appliances/\[\^/\]\+/storage/action\$$")

#: How much longer than the route's own budget the proxy waits. The api's answer
#: is produced AT the budget; the margin covers the reply's trip back.
MARGIN_S = 10


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _locations(text: str) -> dict[str, str]:
    """``location <spec> { ... }`` blocks, brace-matched (an ``if`` nests)."""
    out: dict[str, str] = {}
    for m in re.finditer(r"^\s*location\s+(\S+(?:\s+\S+)?)\s*\{", text, re.M):
        spec = m.group(1).strip()
        depth, i = 1, m.end()
        while depth and i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        out[spec] = text[m.end() : i - 1]
    return out


def _storage_action_block(text: str) -> tuple[str, str]:
    hits = [(spec, body) for spec, body in _locations(text).items() if "storage/action" in spec]
    assert len(hits) == 1, f"expected exactly one storage-action location, found {[s for s, _ in hits]}"
    return hits[0]


def _seconds(directive: str, body: str) -> int:
    m = re.search(rf"{directive}\s+(\d+)s;", body)
    assert m, f"{directive} not set (or not in whole seconds) in the storage-action location"
    return int(m.group(1))


def _directives(body: str) -> set[str]:
    """The proxy directives of a block, whitespace-normalised, comments dropped."""
    out = set()
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(" ".join(line.split()))
    return out


def route_budget_s() -> float:
    """The storage channel's ``enqueue_command(..., timeout=N, channel=CHANNEL_STORAGE)``."""
    src = _text(ROUTE_SOURCE)
    m = re.search(
        r"enqueue_command\([^)]*?timeout=(\d+(?:\.\d+)?),\s*channel=_cmd\.CHANNEL_STORAGE", src, re.S
    )
    assert m, "could not read the storage action route's enqueue timeout from supervisor.py"
    return float(m.group(1))


def supervisor_report_s() -> float:
    """How long the supervisor waits for the host runner before reporting."""
    m = re.search(r"^_RESULT_TIMEOUT_S\s*=\s*(\d+(?:\.\d+)?)", _text(SUPERVISOR_SOURCE), re.M)
    assert m, "could not read _RESULT_TIMEOUT_S from storage_proxy.py"
    return float(m.group(1))


def test_the_budgets_are_read_from_source() -> None:
    """The numbers the other tests compare are the product's, not this file's."""
    assert route_budget_s() == 90.0
    assert supervisor_report_s() == 60.0


def test_the_route_outlasts_the_supervisors_own_report() -> None:
    """The supervisor's "runner did not answer" report can only reach the operator
    if the route is still waiting when it arrives. Lowering the route's budget
    under the supervisor's wait would lose the more specific of the two messages."""
    assert route_budget_s() > supervisor_report_s(), (
        f"the route waits {route_budget_s()}s but the supervisor reports after "
        f"{supervisor_report_s()}s, so its report could never arrive"
    )


@CONFIGS
def test_the_storage_action_has_its_own_exact_path_location(path: Path) -> None:
    spec, _body = _storage_action_block(_text(path))
    assert STORAGE_ACTION_SPEC.match(spec), (
        f"{path.name}: {spec!r} is not the exact-path regex for the storage action"
    )


@CONFIGS
def test_the_proxy_waits_longer_than_the_route(path: Path) -> None:
    """The route answers AT its budget; the proxy must still be listening then."""
    _spec, body = _storage_action_block(_text(path))
    read = _seconds("proxy_read_timeout", body)
    assert read >= route_budget_s() + MARGIN_S, (
        f"{path.name}: proxy_read_timeout {read}s does not outlast the route's "
        f"{route_budget_s():.0f}s budget (+{MARGIN_S}s margin): nginx would answer for the "
        f"api and the product's own message would never reach the client (#1080)"
    )
    assert _seconds("proxy_send_timeout", body) >= read


@CONFIGS
def test_the_generic_api_budget_would_not_have_been_enough(path: Path) -> None:
    """Why the dedicated location exists: the inherited ``/api/`` budget is shorter
    than the route's. If that ever changes the dedicated block is redundant, not
    wrong -- but the assertion documents the reason it was added."""
    locs = _locations(_text(path))
    generic = _seconds("proxy_read_timeout", locs["/api/"])
    assert generic < route_budget_s(), (
        f"{path.name}: the generic /api/ budget ({generic}s) now outlasts the route; "
        "the dedicated storage-action location can be folded back"
    )


@CONFIGS
def test_it_keeps_the_json_error_page_and_the_api_proxy_directives(path: Path) -> None:
    """A dedicated location is a full copy of how ``/api/`` proxies, not a
    shortcut: the JSON error page (#1083), the forwarded headers, HTTP/1.1."""
    locs = _locations(_text(path))
    _spec, body = _storage_action_block(_text(path))
    assert re.search(r"error_page\s+502\s+504\s+@api_unavailable;", body), (
        f"{path.name}: the storage-action location must send 502/504 to the JSON page"
    )
    generic = {d for d in _directives(locs["/api/"]) if not d.startswith("proxy_read_timeout")}
    ours = {d for d in _directives(body) if not d.startswith(("proxy_read_timeout", "proxy_send_timeout"))}
    assert generic <= ours, f"{path.name}: missing from the storage-action location: {generic - ours}"


def test_both_copies_carry_the_same_storage_action_block() -> None:
    """Two hand-maintained copies; nothing but review keeps them in step."""
    blocks = []
    for path in (IMAGE_TEMPLATE, APPLIANCE_TEMPLATE):
        spec, body = _storage_action_block(_text(path))
        blocks.append((spec, _directives(body)))
    assert blocks[0] == blocks[1], "the two nginx templates drifted on the storage-action location"
