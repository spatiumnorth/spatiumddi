"""Release version strings, and whether a build includes a release (#1183).

SpatiumDDI releases are CalVer (``YYYY.MM.DD-N``) until 1.0.0 and SemVer
from then on (#1182). Every SemVer release is newer than every CalVer one.
Builds that are not releases report other strings:

* a nightly: ``0.0.0-nightly-YYYYMMDD+<sha>``, built from main on that date;
* a local or dev build: ``dev``, ``dev-<sha>-<rand>``, ``latest``, or a
  ``0.x`` placeholder from packaging metadata.

Never compare version strings as strings. ``"1.0.0" > "2026.09.04-1"`` is
false, and so is ``"1.0.10" > "1.0.9"``.

The frontend mirrors this in ``frontend/src/lib/versions.ts``; keep the two
in step.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

_CALVER_RE = re.compile(r"^(\d{4})\.(\d{2})\.(\d{2})(?:-(\d+))?$")
_SEMVER_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)
_NIGHTLY_RE = re.compile(r"^0\.0\.0-nightly-(\d{4})(\d{2})(\d{2})(?:\+[0-9A-Za-z.-]+)?$")


@dataclass(frozen=True, order=True)
class Release:
    """A release version. Instances compare in release order."""

    # (0, year, month, day, n) for CalVer, (1, major, minor, patch, pre)
    # for SemVer: the leading scheme puts every SemVer release after every
    # CalVer one.
    key: tuple
    # The day a CalVer release was tagged. A SemVer tag carries no date.
    tagged_on: date | None = field(default=None, compare=False)


def _prerelease_key(pre: str | None) -> tuple:
    """SemVer §11 precedence: a pre-release sorts before its release, and
    numeric identifiers sort numerically and before alphanumeric ones."""
    if pre is None:
        return (1,)
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (0, parts)


def parse_release(version: str | None) -> Release | None:
    """The release ``version`` names, or None if it names none.

    None covers the empty string, dev and nightly builds, placeholders like
    ``0.1.0``, and anything unparseable. A SemVer release starts at 1.0.0,
    so the ``0.x`` placeholders never parse as releases.
    """
    value = (version or "").strip()
    match = _CALVER_RE.match(value)
    if match:
        year, month, day, n = match.groups()
        try:
            tagged_on = date(int(year), int(month), int(day))
        except ValueError:
            return None
        return Release((0, tagged_on.year, tagged_on.month, tagged_on.day, int(n or 0)), tagged_on)
    match = _SEMVER_RE.match(value)
    if match:
        major, minor, patch, pre = match.groups()
        if int(major) < 1:
            return None
        return Release((1, int(major), int(minor), int(patch), _prerelease_key(pre)))
    return None


def nightly_build_date(version: str | None) -> date | None:
    """The day a nightly build was cut from main, or None if ``version`` is
    not a nightly."""
    match = _NIGHTLY_RE.match((version or "").strip())
    if not match:
        return None
    try:
        return date(*(int(g) for g in match.groups()))
    except ValueError:
        return None


_BARE_NIGHTLY_RE = re.compile(r"^nightly-(\d{8})$")


def canonical_version(version: str | None, build_stamp: str | None = None) -> str:
    """The one spelling of a running build's version (#2111).

    A nightly's images are tagged ``nightly-YYYYMMDD`` (the Helm ``image.tag``,
    so ``VERSION`` in the api), while its agents, supervisor and appliance
    slot report ``0.0.0-nightly-YYYYMMDD+<sha>``. This maps the bare tag onto
    the second form, taking the ``+<sha>`` from ``build_stamp`` (the build's
    own stamp, baked as ``APP_VERSION``) when that names the same night.
    Anything that is not a bare nightly tag is returned unchanged.
    """
    value = (version or "").strip()
    match = _BARE_NIGHTLY_RE.match(value)
    if not match:
        return value
    stamp = (build_stamp or "").strip()
    night = nightly_build_date(stamp)
    if night is not None and f"{night:%Y%m%d}" == match.group(1):
        return stamp
    candidate = f"0.0.0-nightly-{match.group(1)}"
    return candidate if nightly_build_date(candidate) is not None else value


def includes_release(version: str | None, release: str) -> bool | None:
    """Whether a build reporting ``version`` has everything in ``release``.

    True or False when that is known, None when it is not: a dev build, an
    unparseable string, a nightly cut on the release's own date (it may have
    been built before the tag), or a nightly measured against a SemVer
    release (a SemVer tag carries no date to compare with). A nightly is
    built from main, so it has every CalVer release tagged before its date.

    ``release`` must name a release; anything else is a programming error.
    """
    target = parse_release(release)
    if target is None:
        raise ValueError(f"not a release version: {release!r}")
    built = parse_release(version)
    if built is not None:
        return built >= target
    nightly = nightly_build_date(version)
    if nightly is None or target.tagged_on is None or nightly == target.tagged_on:
        return None
    return nightly > target.tagged_on


def upgrade_direction(installed: str | None, target: str | None) -> str:
    """Whether moving a node from ``installed`` to ``target`` goes forward:
    ``"forward"``, ``"same"``, ``"backward"`` or ``"unknown"``.

    ``"backward"`` covers a nightly that already includes the target:
    installing the release would drop whatever main gained since.
    ``"unknown"`` covers a target that is not a release, and an installed
    build whose relation to it cannot be known (a dev build, or a nightly
    cut on the tag's own day).
    """
    to = parse_release(target)
    if to is None:
        return "unknown"
    installed_release = parse_release(installed)
    if installed_release is not None:
        if to > installed_release:
            return "forward"
        return "same" if to == installed_release else "backward"
    includes = includes_release(installed, (target or "").strip())
    if includes is None:
        return "unknown"
    return "backward" if includes else "forward"


_NIGHTLY_TAG_RE = re.compile(r"^nightly-(\d{4})\.?(\d{2})\.?(\d{2})$")


def is_installed_target(installed: str | None, target: str | None) -> bool:
    """Whether a node reporting ``installed`` is already running ``target`` (#3026).

    A release is installed under its own tag, so the two strings are equal.
    A nightly is not: its release tag is ``nightly-YYYY.MM.DD`` (the bare
    image tag ``nightly-YYYYMMDD`` is accepted too) while the slot reports
    ``0.0.0-nightly-YYYYMMDD+<sha>``. A plain string compare never matched
    them, so a completed nightly upgrade stayed "pending" and the supervisor
    could fire it again over the rollback slot.
    """
    installed = (installed or "").strip()
    target = (target or "").strip()
    if not installed or not target:
        return False
    if installed == target:
        return True
    night = nightly_build_date(installed)
    match = _NIGHTLY_TAG_RE.match(target)
    if night is None or match is None:
        return False
    return f"{night:%Y%m%d}" == "".join(match.groups())
