"""The daily update check's version comparison (#1182).

``_is_newer`` compared the two tags as strings. That was already wrong
within CalVer (``"2026.04.22-10" > "2026.04.22-2"`` is false, contrary to
the comment above it), and across the switch to SemVer it would hide 1.0.0
from every install: ``"1.0.0" > "2026.09.04-1"`` is false. Nothing tested
it.
"""

from __future__ import annotations

import pytest

from app.tasks.update_check import _is_newer


@pytest.mark.parametrize(
    ("latest", "running", "expected"),
    [
        # CalVer
        ("2026.09.04-1", "2026.08.12-1", True),
        ("2026.08.12-1", "2026.09.04-1", False),
        ("2026.09.04-1", "2026.09.04-1", False),
        ("2026.04.22-10", "2026.04.22-2", True),
        # the switch: every SemVer release is newer than every CalVer one
        ("1.0.0", "2026.09.04-1", True),
        ("2026.12.31-9", "1.0.0", False),
        # SemVer
        ("1.0.10", "1.0.9", True),
        ("1.1.0", "1.0.10", True),
        ("1.0.0", "1.0.0-rc.1", True),
        ("1.0.0-rc.2", "1.0.0-rc.1", True),
        ("1.0.0", "1.0.1", False),
        # a leading "v" on either side
        ("v1.0.0", "2026.09.04-1", True),
        ("v2026.09.04-1", "v2026.09.04-1", False),
    ],
)
def test_releases_compare_in_release_order(latest: str, running: str, expected: bool) -> None:
    assert _is_newer(latest, running) is expected


@pytest.mark.parametrize("running", ["dev", "", "latest", "dev-abc1234-x9", "0.1.0", "unknown"])
def test_an_untagged_build_is_offered_any_release(running: str) -> None:
    """Placeholders are unknown, never versions. ``latest`` (the
    ``.env.example`` default) used to compare as a string and sort above
    every tag, so those installs were never offered an update."""
    assert _is_newer("2026.09.04-1", running) is True
    assert _is_newer("1.0.0", running) is True


def test_a_nightly_is_offered_only_releases_it_does_not_have() -> None:
    nightly = "0.0.0-nightly-20260924+7490f61"
    assert _is_newer("2026.09.04-1", nightly) is False  # tagged before it was built
    assert _is_newer("2026.09.30-1", nightly) is True
    assert _is_newer("2026.09.24-1", nightly) is True  # same day: may predate the tag
    assert _is_newer("1.0.0", nightly) is True  # a SemVer tag carries no date


@pytest.mark.parametrize("latest", ["", "latest", "nightly", "0.0.0-nightly-20260924+abc", "0.1.0"])
def test_a_latest_that_is_not_a_release_offers_nothing(latest: str) -> None:
    assert _is_newer(latest, "2026.09.04-1") is False
    assert _is_newer(latest, "dev") is False
