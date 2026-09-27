"""Slot-image URL re-fire-nonce version gate (#419).

The control plane appends a per-apply nonce as a URL ``#fragment`` so a fresh
apply of the same image re-fires the supervisor trigger. The host runner only
strips that fragment before fetching as of #386, first released in
2026.06.12-2; an older appliance hands it straight to the downloader and the
apply wedges at "in-flight" forever. ``supervisor_strips_url_fragment`` gates
the nonce so only known-capable appliances get it. It lives in
``services.appliance.slot_image_target`` alongside the resolver + stamper both
scheduling surfaces share (#787).

The runner ships in the slot OS, so the installed appliance version decides
and the supervisor's version is only the fallback (#1183). Every supervisor
reported a frozen ``2026.05.14.1`` until #1183, and reading that first sent
every appliance down the clean-URL path.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.appliance.slot_image_target import supervisor_strips_url_fragment

FROZEN = "2026.05.14.1"  # what every supervisor reported until #1183


@pytest.mark.parametrize(
    ("supervisor_version", "installed_version", "expected"),
    [
        # The appliance's installed version decides.
        (FROZEN, "2026.09.04-1", True),  # #1183: every appliance, until now
        (FROZEN, "2026.06.12-2", True),  # the first release with #386
        (FROZEN, "2026.06.12-1", False),  # tagged before #386 merged
        (FROZEN, "2026.06.11-1", False),  # Nuvopact's box
        (FROZEN, "1.0.0", True),  # SemVer is newer than every CalVer release
        ("2026.09.04-1", "2026.06.11-1", False),  # a newer supervisor doesn't help
        # A nightly has every release tagged before its date.
        (None, "0.0.0-nightly-20260925+abc1234", True),
        (None, "0.0.0-nightly-20260610+abc1234", False),
        # The supervisor's version is the fallback when the installed one
        # is missing or can't be placed.
        ("2026.06.13-2", None, True),
        ("2026.06.11-1", None, False),
        ("2026.09.04-1", "dev-abc1234-9f2e", True),
        # Nothing known → safe clean-URL path.
        (None, None, False),
        (FROZEN, None, False),
        ("dev-abc1234", None, False),
        ("dev", "dev-abc1234-9f2e", False),
        ("", "", False),
        # A nightly cut on the release's own date may predate the tag.
        (None, "0.0.0-nightly-20260612+abc1234", False),
    ],
)
def test_supervisor_strips_url_fragment(
    supervisor_version: str | None,
    installed_version: str | None,
    expected: bool,
) -> None:
    row = SimpleNamespace(
        supervisor_version=supervisor_version,
        installed_appliance_version=installed_version,
    )
    assert supervisor_strips_url_fragment(row) is expected  # type: ignore[arg-type]
