#!/usr/bin/env python3
"""Fail CI when a NEW route publishes no response schema (issue #917).

A FastAPI route with no ``response_model`` whose handler returns a bare
``dict`` publishes ``{}`` as its response schema. A generated client gets an
untyped container for it, so every field access is stringly-typed and every
rename is a silent break — the same failure #907 fixed for nullable
properties, arriving through a different door.

~113 routes were in that state when #917 was filed. Retyping all of them at
once is not the point; **stopping the set from growing** is, so this works the
way ``lint_migrations.py`` does: a checked-in baseline of the known-untyped
routes, and a non-zero exit for anything not in it.

Split into two modes because they need different environments — the same
reason ``make openapi`` runs the exporter inside the API image:

* ``--list`` imports the app and prints every untyped route. Needs FastAPI,
  so it runs inside the API container.
* ``--check FILE`` compares that listing against the baseline. Pure stdlib,
  so it runs anywhere, including a bare CI runner.

Chain them with ``&&`` when invoking by hand — a failed ``--list`` must never
reach ``--check``::

    python3 scripts/lint_untyped_routes.py --list > /tmp/ur.txt \
      && python3 scripts/lint_untyped_routes.py --check /tmp/ur.txt

``make lint-untyped-routes`` wires the two together; ``--baseline FILE``
re-records. Re-record only when *removing* entries: a new one means a route
shipped without a schema, which is the thing this exists to catch — type the
route instead.

The split is also the guard's own weak point (issue #1030). ``--list`` writes
its findings to stdout, so when it FAILS it writes nothing — and ``--check``
then compared an empty file against the baseline, found no unbaselined route,
and reported ``OK — 0 untyped route(s), all baselined.`` Exit 0: a green that
meant the guard had evaluated nothing. An import-time error in the app is
exactly the kind of change this is meant to be watching, so any such error
silently disabled it. ``--check`` now refuses an empty listing whenever the
baseline is not empty, which is the same fail-closed rule ``appliance-verify-
arch`` and ``bake-images.sh`` already follow.

The listing walks the live ``app.routes`` rather than parsing source, because
that is what actually reaches the OpenAPI document: a decorator this script
could not parse would otherwise pass silently.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = REPO_ROOT / "backend" / "untyped_routes_baseline.txt"


def _load_routes() -> list[tuple[str, str]]:
    """``(METHOD, path)`` for every operation whose 200 response is an
    unconstrained object.

    Detection runs against the **generated OpenAPI document**, not against
    ``route.response_model``, because FastAPI infers a response model from the
    handler's return annotation: a route annotated ``-> dict[str, Any]`` has a
    non-None ``response_model`` and still publishes ``{"type": "object"}`` with
    no properties. The client-facing symptom is the untyped schema, so that is
    what is measured — checking the attribute would have reported zero
    findings while every one of these routes stayed unusable to a generator.

    Imports the app, so it needs FastAPI — run inside the API image.
    """
    # Same self-location as ``scripts/export_openapi.py``: run from a plain
    # checkout, Python puts ``scripts/`` on the path rather than the repo
    # root, so ``backend`` never lands there. Inside the API image there is no
    # ``backend/`` at all and ``PYTHONPATH=/app`` already covers it.
    backend = REPO_ROOT / "backend"
    if backend.is_dir():
        sys.path.insert(0, str(backend))
    os.environ.setdefault("SECRET_KEY", "lint-only-not-a-real-secret")
    # A lint-only key is exactly what the app refuses to boot on (#1222).
    os.environ.setdefault("ALLOW_INSECURE_SECRET_KEY", "true")
    os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://lint@localhost/lint")

    from fastapi.routing import APIRoute  # noqa: PLC0415
    from starlette.responses import JSONResponse, Response  # noqa: PLC0415

    from app.main import app  # noqa: PLC0415

    # Routes that return a Response subclass — file downloads, SSE streams —
    # have no JSON body to describe, so a missing schema is correct rather
    # than a gap. FastAPI still lists a 200 with an application/json content
    # block for them, so they have to be excluded by inspecting the handler.
    #
    # Two things make that awkward, and both bit the first cut of this script:
    #
    # 1. ``app.routes`` on this FastAPI version holds ``_IncludedRouter``
    #    wrappers, not a flat list of ``APIRoute`` — a plain walk found ZERO
    #    routes and silently excluded nothing. The real routes hang off
    #    ``original_router`` and have to be recursed into.
    # 2. Every router module uses ``from __future__ import annotations``, so
    #    ``__annotations__`` holds STRINGS. ``issubclass`` never matches.
    #
    # Paths on the nested routes are router-local, so the exclusion is keyed
    # on ``(method, local_path)`` and matched as a suffix of the document
    # path. A suffix collision would only ever exclude a route that is
    # *already* a stream on the same method and tail, so the failure mode is
    # not silently hiding a typed-able route.
    def _returns_raw_response(endpoint: object) -> bool:
        """True when the handler returns a Starlette ``Response`` subclass.

        Resolved against the handler's own module globals rather than matched
        on the NAME. An earlier cut used ``name.endswith("Response")``, which
        exempted every Pydantic model called ``*Response`` — i.e. most of the
        already-typed API — from the guard entirely, so a future
        ``FooResponse`` with an empty schema would have slipped straight
        through the check that exists to catch it.

        The annotation is a string here (every router module uses
        ``from __future__ import annotations``), so ``issubclass`` on the raw
        value never matches — the lookup has to happen explicitly.
        """
        annotation = getattr(endpoint, "__annotations__", {}).get("return")
        module = sys.modules.get(getattr(endpoint, "__module__", ""), None)

        def _is_raw(name: object) -> bool:
            resolved = name if isinstance(name, type) else getattr(module, str(name).strip(), None)
            if not (isinstance(resolved, type) and issubclass(resolved, Response)):
                return False
            # A ``JSONResponse`` handler DOES return a JSON body — it just
            # bypasses the response model to do it, which is precisely the
            # untyped case this guard is for. Excluded from the exclusion.
            return not issubclass(resolved, JSONResponse)

        if isinstance(annotation, type):
            return _is_raw(annotation)
        if not isinstance(annotation, str):
            return False
        # Unions are real here: the upgrade-image download is annotated
        # ``FileResponse | StreamingResponse`` because it serves from local
        # disk or proxies the mirror. Every arm has to be a raw response for
        # the route to have no JSON body worth describing.
        arms = [a.split("[")[0].strip() for a in annotation.split("|")]
        return bool(arms) and all(_is_raw(a) for a in arms)

    def _api_routes(routes: object, prefix: str = "", depth: int = 0) -> list[tuple[str, str]]:
        """``(METHOD, full_path)`` for every route that returns a Response.

        The include prefix is accumulated on the way down: a route's own
        ``path`` is router-local, so matching on it alone would exclude far
        more than intended — an early cut of this script matched by path
        SUFFIX and silently dropped 105 of 109 findings, because local paths
        like ``/{id}`` are a suffix of half the API.
        """
        found: list[tuple[str, str]] = []
        for route in routes:  # type: ignore[attr-defined]
            if isinstance(route, APIRoute):
                if _returns_raw_response(route.endpoint):
                    for method in route.methods or set():
                        found.append((method.upper(), prefix + route.path))
            inner = getattr(route, "original_router", None)
            if inner is not None and depth < 10:
                context = getattr(route, "include_context", None)
                found.extend(
                    _api_routes(
                        getattr(inner, "routes", []),
                        prefix + (getattr(context, "prefix", "") or ""),
                        depth + 1,
                    )
                )
        return found

    raw_response_ops = set(_api_routes(app.routes))

    document = app.openapi()
    schemas = (document.get("components") or {}).get("schemas") or {}

    def _is_untyped(schema: dict[str, object] | None) -> bool:
        if schema is None:
            return False
        ref = schema.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            return _is_untyped(schemas.get(ref.rsplit("/", 1)[-1]))
        # ``{}`` or ``{"type": "object"}`` with nothing else said about it.
        # ``additionalProperties`` alone does not count as typed: a client
        # still gets a dictionary rather than a model.
        if schema.get("properties") or schema.get("allOf") or schema.get("anyOf"):
            return False
        if schema.get("oneOf") or schema.get("enum") or schema.get("items"):
            return False
        declared = schema.get("type")
        return declared in (None, "object")

    out: list[tuple[str, str]] = []
    for path, item in (document.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            if not isinstance(operation, dict):
                continue
            ok = (operation.get("responses") or {}).get("200")
            if not isinstance(ok, dict):
                continue
            content = ok.get("content") or {}
            body = content.get("application/json")
            if not isinstance(body, dict):
                # No JSON body to describe — a file download or a stream.
                continue
            if (method.upper(), path) in raw_response_ops:
                continue
            if _is_untyped(body.get("schema")):
                out.append((method.upper(), path))
    return sorted(set(out))


_HEADER = (
    "# Routes that publish no response schema (issue #917).\n"
    "# Generated by: make lint-untyped-routes-baseline\n"
    "# This list may SHRINK, never grow — a new entry means a route shipped\n"
    "# without a response_model. Type the route instead.\n"
)


def _format(rows: list[tuple[str, str]]) -> list[str]:
    return [f"{method} {path}" for method, path in rows]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true", help="Print untyped routes (needs FastAPI).")
    mode.add_argument("--check", metavar="FILE", help="Compare FILE against the baseline.")
    mode.add_argument("--baseline", metavar="FILE", help="Re-record the baseline from FILE.")
    parser.add_argument(
        "--baseline-path",
        default=str(DEFAULT_BASELINE),
        help="Where the baseline lives (default: backend/untyped_routes_baseline.txt).",
    )
    args = parser.parse_args()

    if args.list:
        for row in _format(_load_routes()):
            print(row)
        return 0

    source = Path(args.check or args.baseline)
    if not source.exists():
        print(f"Listing not found: {source}", file=sys.stderr)
        return 1
    current = sorted(
        line.strip()
        for line in source.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    )

    baseline_path = Path(args.baseline_path)
    if args.baseline:
        baseline_path.write_text(_HEADER + "\n".join(current) + "\n")
        print(f"Wrote {len(current)} entries to {baseline_path}")
        return 0

    if not baseline_path.exists():
        print(f"Baseline missing: {baseline_path}", file=sys.stderr)
        print("Run: make lint-untyped-routes-baseline", file=sys.stderr)
        return 1

    known = {
        line.strip()
        for line in baseline_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }

    # Fail closed on an empty listing (#1030). The producer is a separate
    # process; if it died, this one is handed an empty file and every
    # comparison below trivially passes. An empty listing is only ever
    # legitimate when the baseline is empty too — i.e. when there is
    # genuinely nothing left untyped, at which point the baseline should
    # have been re-recorded to match.
    #
    # Checked for --check only: --baseline is how an operator RECORDS an
    # empty set, so refusing there would make the last route impossible to
    # retire.
    if args.check and not current and known:
        print(
            f"Empty listing: {source} contains no routes, but the baseline has "
            f"{len(known)}.",
            file=sys.stderr,
        )
        print(
            "The --list step that produces it almost certainly failed (an\n"
            "import-time error in the app is the usual cause). Re-run it and\n"
            "read its stderr:\n"
            "  python3 scripts/lint_untyped_routes.py --list",
            file=sys.stderr,
        )
        return 1

    new = [row for row in current if row not in known]
    # Fixed routes are reported but do not fail: the baseline should keep
    # shrinking, and a stale entry is untidy rather than dangerous.
    fixed = sorted(known - set(current))

    if new:
        print("New routes with no response schema:\n", file=sys.stderr)
        for row in new:
            print(f"  {row}", file=sys.stderr)
        print(
            "\nA route with no response_model publishes '{}' as its schema, so a\n"
            "generated client gets an untyped container (issue #917). Declare a\n"
            "response_model, or -- if the route returns a Response subclass --\n"
            "annotate the handler with it.",
            file=sys.stderr,
        )
        return 1

    if fixed:
        print(f"{len(fixed)} baselined route(s) now typed — re-record the baseline:")
        for row in fixed[:20]:
            print(f"  {row}")
        print("  make lint-untyped-routes-baseline")

    print(f"OK — {len(current)} untyped route(s), all baselined.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
