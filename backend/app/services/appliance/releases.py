"""GitHub release listing (Phase 4c) + upgrade-image asset discovery (#199).

Lists published SpatiumDDI releases from the GitHub API and reports the
currently-installed version, so the Releases tab can show "what's
available" + "what you're running". Read-only.

#199 adds upgrade-image asset discovery on top of the same fetch: for
appliances with internet access the control plane can list the releases
that carry the appliance upgrade-image ``.raw.xz`` asset + its
``.sha256`` sidecar, so the Fleet → Upgrade images picker has something
to import from (vs. the air-gap upload path). The raw GitHub response is
fetched + cached once and both the plain release list + the asset-aware
list build from it.

#294 — the old one-click "apply" half of this module (a trigger file
watched by a host-side ``spatiumddi-update.path`` unit running
``docker-compose pull && up -d``) was removed: it's a pre-#183
docker-compose-era mechanism that does nothing on the k3s appliance
(no compose stack, no such unit). OS upgrades on the appliance go
through the A/B slot image flow (``services/appliance/slot.py``,
surfaced on the Fleet tab); docker/k8s control planes use the
operator-run ``docker compose`` / ``helm upgrade`` commands shown in
the UI's manual-upgrade modal.

Cache: GitHub release listings are public + rate-limited (60 req/h
unauthenticated). 60-second in-memory cache keeps the page snappy
without burning the budget.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

_GITHUB_API = "https://api.github.com"
_CACHE_TTL_SECONDS = 60
# #2410 — one GitHub page is enough to see past a run of nightlies (two
# architectures a day is ~50 releases a month), and 100 is the API's cap.
_FETCH_PER_PAGE = 100
# The upgrade-image window: walk the listing newest-first until this many
# NON-nightly releases are seen, so a month of nightlies can never push
# the last stable release out of the picker.
_STABLE_WINDOW = 25

# Appliance upgrade-image asset-name convention the release workflow
# attaches to every cut (see .github/workflows/release.yml):
#   spatiumddi-appliance-slot-amd64.raw.xz            (stable)
#   spatiumddi-appliance-slot-<VERSION>-amd64.raw.xz  (versioned)
# plus a matching ``.sha256`` sibling for each. Both names point at the
# same bytes — but only on the CURRENT latest release: the stable pair
# exists solely to back ``releases/latest/download/<name>`` and #392's
# retention prunes it from every release the moment a newer one is cut.
# So a per-tag URL must use the versioned name, which is why the picker
# below sorts longest-first.
# #1026 — the arch suffix is CAPTURED rather than hardcoded to amd64.
# It is the one trustworthy statement of an imported image's
# architecture: this name comes from a release WE published, over the
# GitHub API, not from a file an operator named. (The upload path has no
# equivalent and takes the operator's word — see the column comment on
# ``ApplianceUpgradeImage.architecture`` for why reading it out of the
# bytes is not cheap, and why the host runner re-checks either way.)
_UPGRADE_IMAGE_ASSET_RE = re.compile(
    r"^spatiumddi-appliance-slot.*-(?P<arch>amd64|arm64)\.raw\.xz$"
)


@dataclass
class Release:
    tag: str
    name: str
    published_at: datetime
    body: str
    html_url: str
    is_prerelease: bool
    is_installed: bool


@dataclass
class UpgradeImageRelease:
    """A release that carries an importable appliance upgrade image."""

    tag: str
    name: str
    published_at: datetime
    body: str
    html_url: str
    is_prerelease: bool
    is_installed: bool
    image_asset_url: str
    checksum_asset_url: str
    size_bytes: int | None
    # #1026 — from the asset name. A release that publishes both
    # architectures yields one row per architecture, so the picker can
    # show (and the importer can select) the right one rather than
    # whichever sorted first.
    architecture: str


# Cache the raw GitHub release dicts so both ``list_releases`` (plain)
# and ``list_available_upgrade_images`` (asset-aware) build from one
# fetch.
_RAW_CACHE: dict[str, tuple[datetime, list[dict]]] = {}


def release_channel(tag: str, is_prerelease: bool = False) -> str:
    """``nightly`` / ``prerelease`` / ``stable`` for a release tag (#2410).

    Display-only: derived from the tag and GitHub's own prerelease flag,
    not a subscription setting (that is #149).
    """
    t = tag.lower()
    if t.startswith("nightly"):
        return "nightly"
    if is_prerelease or "-rc" in t or "-beta" in t or "-alpha" in t:
        return "prerelease"
    return "stable"


def _upgrade_image_window(data: list[dict]) -> list[dict]:
    """Newest-first slice holding ``_STABLE_WINDOW`` non-nightly releases."""
    out: list[dict] = []
    stable = 0
    for r in data:
        out.append(r)
        if release_channel(r.get("tag_name", ""), bool(r.get("prerelease", False))) != "nightly":
            stable += 1
            if stable >= _STABLE_WINDOW:
                break
    return out


def peek_upgrade_image_releases() -> list[UpgradeImageRelease]:
    """Importable-image rows from the release cache, with NO network call.

    Used to decorate the staged list: an air-gapped control plane must
    not wait out a GitHub timeout on every page load. Stale entries are
    fine here (the TTL only bounds how often the picker refetches), and a
    cold cache is simply an empty list.
    """
    cached = _RAW_CACHE.get("raw")
    if not cached:
        return []
    now = datetime.now(UTC)
    installed = get_installed_version()
    out: list[UpgradeImageRelease] = []
    for r in _upgrade_image_window(cached[1]):
        out.extend(_to_upgrade_image_releases(r, installed, now))
    return out


def get_installed_version() -> str:
    """The version currently running — read from settings.version, which
    the compose env populates from ``SPATIUMDDI_VERSION`` in .env."""
    return settings.version or "dev"


def _parse_published(r: dict, fallback: datetime) -> datetime:
    published = r.get("published_at") or r.get("created_at")
    if not isinstance(published, str):
        return fallback
    try:
        return datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        return fallback


async def _fetch_raw_releases() -> list[dict] | None:
    """Fetch + cache the most-recent GitHub releases (raw API dicts).

    Returns ``None`` on any error (rate-limited, network unreachable,
    repo name typo) so callers can distinguish "GitHub unreachable"
    from "reachable but no matching releases".
    """
    now = datetime.now(UTC)
    cached = _RAW_CACHE.get("raw")
    if cached and (now - cached[0]).total_seconds() < _CACHE_TTL_SECONDS:
        return cached[1]

    url = f"{_GITHUB_API}/repos/{settings.github_repo}/releases"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        # follow_redirects: GitHub answers 301 for a repo that has moved — which
        # an org rename makes routine. httpx does not follow by default and
        # raise_for_status() does not reject a 3xx, so the redirect BODY was
        # parsed as a release: no tag_name, so the check recorded "up to date"
        # with no error and logged success. A silent false negative on an
        # update notifier is worse than a loud failure; following the redirect
        # removes it and keeps a stale github_repo working.
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers, params={"per_page": _FETCH_PER_PAGE})
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("appliance_releases_fetch_failed", error=str(exc))
        return None
    if not isinstance(data, list):
        return None
    _RAW_CACHE["raw"] = (now, data)
    return data


async def list_releases() -> list[Release]:
    """Fetch + cache the most-recent 25 GitHub releases.

    Empty list on any error (rate-limited, network unreachable,
    repo name typo). The UI shows the empty state cleanly.
    """
    data = await _fetch_raw_releases()
    if data is None:
        return []
    now = datetime.now(UTC)
    installed = get_installed_version()
    releases: list[Release] = []
    for r in data[:25]:
        tag = r.get("tag_name", "")
        if not tag:
            continue
        releases.append(
            Release(
                tag=tag,
                name=r.get("name") or tag,
                published_at=_parse_published(r, now),
                body=r.get("body") or "",
                html_url=r.get("html_url", ""),
                is_prerelease=bool(r.get("prerelease", False)),
                is_installed=(tag == installed),
            )
        )
    return releases


def _pick_upgrade_assets(assets: list[dict]) -> dict[str, tuple[str, str, int | None]]:
    """Map each architecture to its ``.raw.xz`` + ``.sha256`` asset pair.

    Returns ``{arch: (image_url, checksum_url, size_bytes)}`` — empty when
    a release carries no matched pair. Prefers the versioned asset name
    (the longer one) per architecture — and that preference is
    load-bearing, not cosmetic: the stable name is pruned from every
    non-latest release (#392), so a URL built from it would 404 for
    anything but the newest cut.

    Skipping a half-pruned release is also deliberate. #392's Tier 2
    keeps the tiny ``.sha256`` provenance sidecar after dropping the
    heavy ``.raw.xz``; requiring the matched PAIR is what makes such a
    release disappear from the picker instead of offering a dead link.

    Keyed by architecture (#1026) rather than returning the first match:
    a release that publishes both would otherwise resolve to whichever
    name happened to be longer, which is a coin flip between an image
    that boots and one that does not.
    """
    by_name = {(a.get("name") or ""): a for a in assets}
    out: dict[str, tuple[str, str, int | None]] = {}
    matches = [
        (n, m.group("arch")) for n in by_name if (m := _UPGRADE_IMAGE_ASSET_RE.match(n)) is not None
    ]
    for raw_name, arch in sorted(matches, key=lambda t: len(t[0]), reverse=True):
        if arch in out:
            continue  # already took the longer (versioned) name for this arch
        sha_name = raw_name[: -len(".raw.xz")] + ".sha256"
        if sha_name not in by_name:
            continue
        image_url = by_name[raw_name].get("browser_download_url")
        sha_url = by_name[sha_name].get("browser_download_url")
        if image_url and sha_url:
            out[arch] = (image_url, sha_url, by_name[raw_name].get("size"))
    return out


def _to_upgrade_image_releases(r: dict, installed: str, now: datetime) -> list[UpgradeImageRelease]:
    """One row per architecture the release publishes an image for."""
    tag = r.get("tag_name", "")
    if not tag:
        return []
    picked = _pick_upgrade_assets(r.get("assets") or [])
    return [
        UpgradeImageRelease(
            tag=tag,
            name=r.get("name") or tag,
            published_at=_parse_published(r, now),
            body=r.get("body") or "",
            html_url=r.get("html_url", ""),
            is_prerelease=bool(r.get("prerelease", False)),
            is_installed=(tag == installed),
            image_asset_url=image_url,
            checksum_asset_url=sha_url,
            size_bytes=size,
            architecture=arch,
        )
        # Sorted so the listing order is stable across calls rather than
        # following dict insertion, which follows GitHub's asset order.
        for arch, (image_url, sha_url, size) in sorted(picked.items())
    ]


async def list_available_upgrade_images() -> tuple[bool, list[UpgradeImageRelease]]:
    """List releases carrying an importable appliance upgrade image.

    Returns ``(github_reachable, rows)``. ``github_reachable`` is false
    on any fetch error so the picker can default to the air-gap upload
    tab; true + empty means GitHub is reachable but no recent release
    carries the appliance upgrade-image assets.
    """
    data = await _fetch_raw_releases()
    if data is None:
        return (False, [])
    now = datetime.now(UTC)
    installed = get_installed_version()
    out: list[UpgradeImageRelease] = []
    for r in _upgrade_image_window(data):
        out.extend(_to_upgrade_image_releases(r, installed, now))
    return (True, out)


async def get_upgrade_image_assets(
    tag: str, architecture: str | None = None
) -> UpgradeImageRelease | None:
    """Resolve one release tag's upgrade-image asset URLs.

    ``None`` when GitHub is unreachable, the tag isn't found, or the
    release doesn't carry a matched ``.raw.xz`` + ``.sha256`` pair for
    the requested architecture.

    ``architecture=None`` means "the only one there is" and returns
    ``None`` when a release publishes several (#1026) — picking one for
    the caller would be picking which nodes boot afterwards. The
    importer surfaces that as a 422 naming the available choices.
    """
    return (await resolve_upgrade_image_choice(tag, architecture)).spec


@dataclass(frozen=True)
class UpgradeImageChoice:
    """The outcome of resolving one tag + architecture to an asset pair.

    One call rather than "resolve, then ask what was available" (#1026):
    the caller needs both answers to tell a missing asset apart from a
    missing decision, and two calls means two chances for a caller — or
    a test's monkeypatch — to cover only one of them and let the other
    reach the network.
    """

    #: The resolved release, or None when nothing matched.
    spec: UpgradeImageRelease | None
    #: Every architecture this tag publishes an importable image for.
    #: Empty when the tag is unknown or GitHub is unreachable.
    available: tuple[str, ...]


async def resolve_upgrade_image_choice(
    tag: str, architecture: str | None = None
) -> UpgradeImageChoice:
    """Resolve one tag (+ optional architecture) to an importable asset pair."""
    data = await _fetch_raw_releases()
    if data is None:
        return UpgradeImageChoice(spec=None, available=())
    now = datetime.now(UTC)
    installed = get_installed_version()
    for r in data:
        if r.get("tag_name") != tag:
            continue
        rows = _to_upgrade_image_releases(r, installed, now)
        available = tuple(x.architecture for x in rows)
        if architecture is not None:
            spec = next((x for x in rows if x.architecture == architecture), None)
        else:
            # Exactly one, or none — never a guess. See
            # ``get_upgrade_image_assets``.
            spec = rows[0] if len(rows) == 1 else None
        return UpgradeImageChoice(spec=spec, available=available)
    return UpgradeImageChoice(spec=None, available=())
