"""Every POST route declares whether a ``read`` API token may call it (#3302).

The coarse token-scope gate treats a POST as a write unless the handler says
otherwise, so an unclassified POST is *safe* but wrong in one direction: a
monitoring token is refused a route nobody decided to refuse. The old guard
matched route NAMES against a regex (a read-only POST called ``/lookup`` slid
past it) and kept a hand list of "deliberately write" paths whose one-line
reasons were wrong or "not reviewed" - and a wrong reason silences a guard.

Now the decision lives on the handler. A POST under a non-agent prefix carries
exactly one of:

* ``@read_only_post`` - the body is a filter / preview and nothing changes;
* ``@token_write("why")`` - it is a write, or is kept write-scoped on purpose.

~440 POSTs predate this, so the unclassified ones are a checked-in baseline
(``token_unclassified_posts_baseline.txt``, the ``lint_untyped_routes.py``
pattern): it may shrink, never grow, and a stale entry fails too so the file
cannot drift from the tree. Annotate a handler to retire its line.

Routes are walked through FastAPI's ``effective_route_contexts()`` from the
real app, so included routers and routes outside ``/api/v1`` (``/held``) are
covered.

Re-record after retiring entries::

    python tests/test_token_post_classification_3302.py --baseline
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from app.services.api_token_scopes import (
    _AGENT_PREFIXES,
    _path_under,
    is_read_only_post,
    token_write,
    token_write_reason,
)

BASELINE = Path(__file__).resolve().parent.parent / "token_unclassified_posts_baseline.txt"

# Agent-authenticated surfaces: the ``agent`` scope governs them, not the
# read / write split this guard is about.
AGENT_PREFIXES: tuple[str, ...] = _AGENT_PREFIXES

# A POST whose path says it only looks something up. These may never sit in the
# baseline: they are exactly the routes a read token is likely to want, so each
# needs an explicit read_only_post or a reasoned token_write.
_LOOKUP_WORDS = (
    "preview",
    "query",
    "dns-queries",
    "dhcp-audit",
    "dhcp-activity",
    "analytics",
    "search",
    "validate",
    "find-free",
    "plan-allocation",
    "allocation-preview",
    "simulate",
    "lookup",
    "check",
)


def post_routes(app: Any) -> dict[str, Any]:
    """``{path: endpoint}`` for every POST on ``app``, included routers too."""
    found: dict[str, Any] = {}
    for route in app.routes:
        if hasattr(route, "effective_route_contexts"):
            pairs = [(c.path_format, c.original_route) for c in route.effective_route_contexts()]
        else:
            pairs = [(getattr(route, "path", ""), route)]
        for path, r in pairs:
            if "POST" in (getattr(r, "methods", None) or ()) and hasattr(r, "endpoint"):
                found[path] = r.endpoint
    return found


def classify(app: Any) -> tuple[dict[str, Any], list[str], list[str]]:
    """``(posts, unclassified, doubly_marked)`` for the non-agent POSTs."""
    posts = post_routes(app)
    unclassified: list[str] = []
    both: list[str] = []
    for path, ep in sorted(posts.items()):
        if _path_under(path, AGENT_PREFIXES):
            continue
        ro, w = is_read_only_post(ep), token_write_reason(ep) is not None
        if ro and w:
            both.append(path)
        elif not ro and not w:
            unclassified.append(path)
    return posts, unclassified, both


def read_baseline() -> set[str]:
    return {
        line.strip().removeprefix("POST ")
        for line in BASELINE.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


def _real_app() -> Any:
    from app.main import app  # noqa: PLC0415

    return app


def test_no_new_post_route_is_unclassified() -> None:
    _, unclassified, _ = classify(_real_app())
    new = sorted(set(unclassified) - read_baseline())
    assert not new, (
        "POST route(s) declare neither @read_only_post nor @token_write(reason) - decide "
        "whether a read-scoped token may call each (app/services/api_token_scopes.py):\n"
        + "\n".join(new)
    )


def test_the_baseline_only_shrinks() -> None:
    """A line for a route that is now classified, or gone, must be deleted."""
    _, unclassified, _ = classify(_real_app())
    stale = sorted(read_baseline() - set(unclassified))
    assert not stale, (
        "baseline lists POST route(s) that are annotated or no longer exist; "
        "re-record with `python tests/test_token_post_classification_3302.py --baseline`:\n"
        + "\n".join(stale)
    )


def test_a_post_is_not_both_read_only_and_write() -> None:
    _, _, both = classify(_real_app())
    assert not both, both


def test_lookup_shaped_posts_are_never_baselined() -> None:
    """The name heuristic is now only a floor under the baseline: a POST that
    looks like a query / preview must be classified for real."""
    shaped = sorted(
        p for p in read_baseline() if any(w in p.rsplit("/", 1)[-1] for w in _LOOKUP_WORDS)
    )
    assert not shaped, "\n".join(shaped)


def test_every_write_reason_is_a_real_one() -> None:
    posts = post_routes(_real_app())
    for path, ep in posts.items():
        reason = token_write_reason(ep)
        if reason is not None:
            assert len(reason) >= 15, path


def test_token_write_refuses_an_empty_reason() -> None:
    for bad in ("", "x", "not reviewed", "TODO later maybe", "Not reviewed as side-effect free"):
        with pytest.raises(ValueError):
            token_write(bad)
    token_write("Sends probe traffic to the target (outbound)")


def test_the_walk_covers_routes_outside_api_v1() -> None:
    assert "/held" in post_routes(_real_app())


# ── negative control: the guard must actually see an unannotated POST ─────


def _stub_app(*, annotate: bool) -> Any:
    from fastapi import APIRouter, FastAPI  # noqa: PLC0415

    from app.services.api_token_scopes import read_only_post  # noqa: PLC0415

    inner = APIRouter()

    @inner.post("/lookup-thing")
    async def lookup_thing() -> dict[str, str]:  # name fits no regex on purpose
        return {}

    @inner.post("/agents/ingest")
    async def agent_ingest() -> dict[str, str]:
        return {}

    if annotate:
        read_only_post(lookup_thing)

    outer = APIRouter()
    outer.include_router(inner, prefix="/nested")
    app = FastAPI()
    app.include_router(outer, prefix="/outside-api")
    return app


def test_guard_sees_an_unannotated_post_in_an_included_router() -> None:
    _, unclassified, _ = classify(_stub_app(annotate=False))
    assert unclassified == ["/outside-api/nested/agents/ingest", "/outside-api/nested/lookup-thing"]


def test_guard_passes_once_annotated() -> None:
    _, unclassified, _ = classify(_stub_app(annotate=True))
    assert "/outside-api/nested/lookup-thing" not in unclassified


def test_guard_skips_agent_prefixes() -> None:
    from fastapi import APIRouter, FastAPI  # noqa: PLC0415

    r = APIRouter()

    @r.post("/api/v1/dns/agents/heartbeat")
    async def hb() -> dict[str, str]:
        return {}

    app = FastAPI()
    app.include_router(r)
    assert classify(app)[1] == []


def _iter_lines(unclassified: list[str]) -> Iterator[str]:
    for p in unclassified:
        yield f"POST {p}\n"


if __name__ == "__main__":
    if "--baseline" not in sys.argv:
        sys.exit("usage: python tests/test_token_post_classification_3302.py --baseline")
    os.environ.setdefault("ALLOW_INSECURE_SECRET_KEY", "true")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    _, un, _ = classify(_real_app())
    header = (
        "# POST routes that declare neither @read_only_post nor @token_write (#3302).\n"
        "# Generated by: python tests/test_token_post_classification_3302.py --baseline\n"
        "# This list may SHRINK, never grow - a new POST must be annotated.\n"
        "# Annotate a handler, then re-record, to retire its line.\n"
    )
    BASELINE.write_text(header + "".join(_iter_lines(un)))
    print(f"recorded {len(un)} route(s)")
