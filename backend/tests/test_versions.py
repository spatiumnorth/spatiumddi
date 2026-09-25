"""Release versions and ``includes_release`` (#1183).

The frontend mirrors this module in ``frontend/src/lib/versions.ts``, and
``versions.test.ts`` there runs the same cases.
"""

from __future__ import annotations

from datetime import date

import pytest

from app.core.versions import includes_release, nightly_build_date, parse_release


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("2026.06.12-1", "2026.06.12-2"),
        ("2026.06.12", "2026.06.12-1"),
        ("2026.06.12-9", "2026.06.13-1"),
        ("2026.09.04-1", "2026.10.01-1"),
        ("2026.12.31-1", "2027.01.01-1"),
        # Every SemVer release is newer than every CalVer one; as strings,
        # "1.0.0" < "2026.09.04-1".
        ("2026.09.04-1", "1.0.0"),
        ("2099.12.31-9", "1.0.0-rc.1"),
        # Numeric, not lexical: as strings, "1.0.10" < "1.0.9".
        ("1.0.9", "1.0.10"),
        ("1.9.0", "1.10.0"),
        ("1.0.0", "2.0.0"),
        # SemVer §11 pre-release precedence.
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta"),
        ("1.0.0-beta.2", "1.0.0-beta.11"),
        ("1.0.0-rc.1", "1.0.0"),
    ],
)
def test_release_order(older: str, newer: str) -> None:
    a, b = parse_release(older), parse_release(newer)
    assert a is not None and b is not None
    assert a < b
    assert sorted([b, a]) == [a, b]


def test_build_metadata_does_not_affect_order() -> None:
    assert parse_release("1.2.3+abc") == parse_release("1.2.3")


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "dev",
        "dev-abc1234-9f2e",
        "latest",
        # The frozen supervisor string (#1183): a fourth dot-field is not
        # CalVer, so it cannot pass for a release.
        "2026.05.14.1",
        # Packaging placeholders: SemVer-shaped, but a release starts at 1.0.0.
        "0.1.0",
        "0.1.0-dev",
        "0.0.0-dev",
        "0.0.0-nightly-20260925+abc1234",
        "2026.13.01-1",
        "2026.02.30-1",
        "v1.0.0",
        "1.0",
    ],
)
def test_non_releases_do_not_parse(value: str | None) -> None:
    assert parse_release(value) is None


def test_nightly_build_date() -> None:
    assert nightly_build_date("0.0.0-nightly-20260925+abc1234") == date(2026, 9, 25)
    assert nightly_build_date("0.0.0-nightly-20260925") == date(2026, 9, 25)
    assert nightly_build_date("2026.09.25-1") is None
    assert nightly_build_date("0.0.0-nightly-20260231") is None


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2026.06.12-2", True),
        ("2026.06.13-1", True),
        ("1.0.0", True),
        ("2026.06.12-1", False),
        ("2026.06.11-1", False),
        # A nightly is built from main: it has every release tagged before
        # its date, and on the tag's own date it may or may not.
        ("0.0.0-nightly-20260613+abc1234", True),
        ("0.0.0-nightly-20260611+abc1234", False),
        ("0.0.0-nightly-20260612+abc1234", None),
        ("dev-abc1234-9f2e", None),
        ("2026.05.14.1", None),
        (None, None),
    ],
)
def test_includes_a_calver_release(version: str | None, expected: bool | None) -> None:
    assert includes_release(version, "2026.06.12-2") is expected


def test_a_nightly_cannot_be_placed_against_a_semver_release() -> None:
    """A SemVer tag carries no date to compare the nightly's date with."""
    assert includes_release("0.0.0-nightly-20991231+abc", "1.0.0") is None
    assert includes_release("2026.09.04-1", "1.0.0") is False
    assert includes_release("1.0.1", "1.0.0") is True


def test_the_release_must_be_a_release() -> None:
    with pytest.raises(ValueError):
        includes_release("2026.06.12-2", "dev")
