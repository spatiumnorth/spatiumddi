#!/usr/bin/env python3
"""Export the SpatiumDDI OpenAPI document (issue #903).

The native app lives in its own repo (``spatiumnorth/spatiumddi-mobile``), so
the schema is no longer a file a client can read off the working tree — it is
the contract between two repos, and it has to be versioned and fetchable.
``.github/workflows/release.yml`` runs this on every release tag and attaches
the result to the release; the same command reproduces that artifact locally
(``make openapi``) and in the mobile repo's CI.

Three properties make the output a usable contract rather than a snapshot of
whatever the exporting machine happened to have configured:

**It goes through ``app.openapi()``, never ``fastapi.openapi.utils.get_openapi``.**
``create_app()`` replaces ``app.openapi`` with a wrapper that widens
``HTTPValidationError.detail`` to accept the string form ~270 handlers
actually return. Re-deriving the document with ``get_openapi`` would silently
drop that, and a generated client would then reject a large fraction of this
server's real 4xx bodies as schema violations.

**The version is real.** ``info.version`` was hardcoded to ``0.1.0``, so every
release would have published a spec claiming to be 0.1.0 — a generated client
stamped with a version that never changes, which defeats pinning entirely.
``create_app()`` now reads ``settings.version`` (the ``VERSION`` env var the
compose file and the release workflow both already set), and ``--version``
here sets it explicitly.

**It carries the generator normalisations.** That same wrapper also rewrites
OpenAPI 3.1's ``anyOf: [X, {"type": "null"}]`` nullable idiom, which strict
generators answer by dropping the whole property from the generated type —
3,291 schema properties and 297 query parameters, silently, on this document
(#907). A dump that bypasses ``app.openapi()`` publishes a contract whose
clients are missing a third of every model.

**It does not inherit operator branding.** ``info.title`` comes from
``settings.app_title``, which is operator-settable (#886/#888) — exporting on
a branded install would otherwise publish "Acme DDI" as the name of the
public API. The default is pinned below.

Deliberately writes to stdout by default so the caller owns the destination.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Make ``app`` importable from a plain checkout.
#
# Inside the API image this is already true — the image sets
# ``PYTHONPATH=/app`` — but that is the ONE environment where it works by
# accident. Run from a checkout (``python3 scripts/export_openapi.py``, which
# is how ``make openapi`` documents it and how the mobile repo's CI would call
# it) Python puts the SCRIPT's directory on ``sys.path``, not the working
# directory, so ``scripts/`` lands there and ``backend/`` never does — and the
# import below fails with ModuleNotFoundError no matter where you invoke from.
#
# Prepended rather than appended so a real ``backend/app`` wins over anything
# a stray ``app`` directory in the working tree might shadow it with.
_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if (_BACKEND / "app" / "main.py").is_file():
    sys.path.insert(0, str(_BACKEND))

# The document is ~1.8 MB compact / ~3.6 MB at indent=2 (841 paths). Small
# enough to keep on every release forever, which is the point: it is the
# contract for pinning an OLD server version, so it has to outlive the
# heavy-asset keep window in scripts/prune-release-assets.sh. That script's
# ``case`` has a "leave untouched" default branch, so this file is retained
# with no change there — do NOT add a pattern for it.

#: ``info.title`` for the published artifact. Hardcoded rather than read from
#: the environment so the contract is named for the product, not for whichever
#: install ran the export.
CANONICAL_TITLE = "SpatiumDDI"


def build_document(version: str | None) -> dict:
    """Generate the OpenAPI document.

    ``settings`` is a module-level singleton built at import time, so the
    environment has to be set BEFORE ``app.main`` is imported — hence the
    import inside this function rather than at module scope. Reordering these
    two statements silently produces a document carrying the exporting
    machine's title and version instead of the canonical ones.

    Exports the ``app`` that ``app.main`` builds at import, rather than
    calling ``create_app()`` for a second, parallel instance — so the
    artifact is generated from the very object the server serves.

    Not a performance argument: measured in the API image, importing the
    module costs 4.4 s and generating the document 3.5 s, while a second
    ``create_app()`` costs 0.00 s (it re-registers already-imported routers
    and imports nothing). Byte-identical either way; this is simply the
    honest object to export.
    """
    os.environ["APP_TITLE"] = CANONICAL_TITLE
    # The export never signs or decrypts anything, and release.yml runs it
    # with no SECRET_KEY at all, which the app otherwise refuses (#1222).
    os.environ.setdefault("ALLOW_INSECURE_SECRET_KEY", "true")
    if version:
        os.environ["VERSION"] = version
    else:
        # An EMPTY ``VERSION`` is not the same as an absent one: pydantic-
        # settings honours the empty string, so ``settings.version`` becomes
        # "" instead of falling back to "dev". FastAPI asserts on a falsy
        # version ("A version must be provided for OpenAPI"), which is why
        # ``create_app()`` passes ``settings.version or "dev"`` — but the
        # export must not lean on that guard to get ``info.version`` right.
        # Easy to hit — a Make variable that is merely undefined still expands
        # to ``-e VERSION=``, and so does an unset ``GITHUB_REF_NAME``. Drop it
        # so the default applies.
        os.environ.pop("VERSION", None)

    from app.main import app  # noqa: PLC0415 — see docstring

    # ``app.openapi`` is the patched wrapper; see the module docstring for why
    # this must not be ``get_openapi``.
    return app.openapi()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        default=os.environ.get("VERSION"),
        help=(
            "Value for info.version — the release tag in CI (GITHUB_REF_NAME). "
            "Defaults to $VERSION, and to the app's own default ('dev') when "
            "neither is set."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write here instead of stdout.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit without indentation (roughly half the size).",
    )
    args = parser.parse_args()

    doc = build_document(args.version)

    # sort_keys is what makes the artifact BYTE-STABLE. Without it the output
    # tracks dict insertion order, so an unrelated edit that merely moves a
    # router registration produces a diff across the whole document and the
    # release-to-release comparison stops being readable. Sorting is safe:
    # JSON object member order is not significant, and the ordered parts of
    # OpenAPI (``required``, ``enum``, parameter lists) are JSON arrays, whose
    # order sort_keys does not touch.
    if args.compact:
        text = json.dumps(doc, separators=(",", ":"), sort_keys=True)
    else:
        text = json.dumps(doc, indent=2, sort_keys=True)
    # Trailing newline: POSIX text file, and it keeps `sha256sum` output
    # matching between a redirect and an editor round-trip.
    text += "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(
            f"→ wrote {args.output} ({len(text):,} bytes, "
            f"version={doc['info']['version']})",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
