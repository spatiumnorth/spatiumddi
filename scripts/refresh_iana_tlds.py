#!/usr/bin/env python3
"""Regenerate ``backend/app/data/iana_tlds.json`` from IANA's root-zone list.

Run at release-prep. Fetches
``https://data.iana.org/TLD/tlds-alpha-by-domain.txt`` — whose first line
carries ``# Version YYYYMMDDNN`` — and rewrites the ``version`` /
``fetched_at`` / ``tlds`` keys of the bundled file.

The ``special_use`` table in the same file is **hand-curated and preserved
verbatim**: it changes by RFC and by ICANN action, not by download, so this
script never invents it. If the file is missing that key the script refuses
rather than emitting a registry with no special-use entries — which would
silently reclassify every ``.local`` and ``example.com`` zone in every
install as "public" on the next release.

This runs on a developer machine, not in the product: it is not one of the
outbound connections ``docs/PRIVACY.md`` enumerates. The in-product
equivalent is ``POST /api/v1/dns/tld-registry/refresh``, which is
operator-triggered, superadmin-only, and documented there.

Usage:
    python3 scripts/refresh_iana_tlds.py            # rewrite in place
    python3 scripts/refresh_iana_tlds.py --check    # non-zero if stale
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
TARGET = _REPO / "backend" / "app" / "data" / "iana_tlds.json"


def _load_shared_parser():
    """Load ``app/services/dns/tld_registry.py`` straight off disk.

    We use the product's own parser rather than keeping a second copy: the
    point of this script is that a payload it accepts is one the running
    control plane would accept too, and two validators meant to agree is
    the bug class #878 documented at length.

    It is loaded by file path rather than by ``import app.services…``
    because ``app/__init__.py`` installs the #907 datetime patcher at
    import time, which needs pydantic. The module itself is stdlib-only,
    so this keeps the script runnable at release-prep from a bare
    ``python:3.14`` with no backend dependencies installed.
    """
    path = _REPO / "backend" / "app" / "services" / "dns" / "tld_registry.py"
    spec = importlib.util.spec_from_file_location("_spatium_tld_registry", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: @dataclass resolves its own module out of
    # sys.modules to evaluate annotations, and blows up with an opaque
    # AttributeError on None if the module is not there yet.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_shared = _load_shared_parser()
parse_tld_payload = _shared.parse_tld_payload
TldPayloadError = _shared.TldPayloadError
# Also from the product, for the same reason: one place defines where the
# list comes from, and docs/PRIVACY.md documents that one place.
SOURCE_URL = _shared.SOURCE_URL


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="report whether the bundled file is behind IANA; write nothing.",
    )
    args = ap.parse_args()

    if not TARGET.exists():
        print(f"error: {TARGET} does not exist — cannot preserve special_use", file=sys.stderr)
        return 2
    existing = json.loads(TARGET.read_text())
    if not existing.get("special_use"):
        print(
            f"error: {TARGET} has no 'special_use' entries. That table is hand-curated; "
            "regenerating without it would reclassify every reserved zone as public.",
            file=sys.stderr,
        )
        return 2

    with urllib.request.urlopen(SOURCE_URL, timeout=30) as resp:  # noqa: S310 — fixed https URL
        text = resp.read().decode("utf-8")
    try:
        version, tlds = parse_tld_payload(text)
    except TldPayloadError as exc:
        # Same guard the product-side refresh applies. Leave the bundled
        # file untouched: a truncated download would relabel every public
        # zone in every install as "undelegated" on the next release.
        print(f"error: refusing to write a bad payload — {exc}", file=sys.stderr)
        return 2

    if args.check:
        current = existing.get("version", "")
        if current == version:
            print(f"up to date (version {version}, {len(tlds)} TLDs)")
            return 0
        print(
            f"stale: bundled {current or '(none)'} != IANA {version} — "
            "run `make tld-registry`",
            file=sys.stderr,
        )
        return 1

    payload = dict(existing)
    payload["source"] = SOURCE_URL
    payload["version"] = version
    payload["fetched_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload["tlds"] = tlds
    TARGET.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {TARGET} — version {version}, {len(tlds)} TLDs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
