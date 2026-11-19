"""The one resolver both slot-upgrade schedulers share (#787).

The per-box Fleet action and the multi-node rolling orchestrator each
used to compose the appliance's desired slot-image state themselves, and
drifted: the orchestrator stamped only version + URL, so an uploaded
image was fetched from our own self-signed HTTPS URL with verification
on and no hash — the #386 failure, re-introduced on that path.

These tests pin the contract that keeps them together.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.services.appliance.slot_image_target import (
    SlotImageResolutionError,
    SlotImageTarget,
    resolve_slot_image_target,
    stamp_desired_slot_image,
)


def _fake_appliance(**overrides) -> SimpleNamespace:
    """An Appliance row carrying every column the stamper reads or writes.

    That docstring is a contract, and #1026 broke it: the stamper started
    reading ``architecture`` (and ``hostname``, for the refusal message)
    and this stub had neither, so every test here died with
    ``AttributeError`` on a SimpleNamespace. A stand-in for a row has to
    carry the columns the code under test actually touches — the
    alternative is a ``getattr(..., None)`` in production that would also
    swallow a genuinely missing attribute.
    """
    return SimpleNamespace(
        **{
            "hostname": "ddi-test",
            # None = UNKNOWN, which is what an appliance whose supervisor
            # predates #1026 reports. It never conflicts, so the existing
            # cases keep exercising the paths they were written for.
            "architecture": None,
            "supervisor_version": None,
            "installed_appliance_version": None,
            "desired_appliance_version": None,
            "desired_slot_image_url": None,
            "desired_slot_image_sha256": None,
            "desired_slot_image_tls_insecure": False,
            **overrides,
        }
    )


class _FakeDB:
    """Stands in for AsyncSession.get()."""

    def __init__(self, image=None) -> None:
        self._image = image

    async def get(self, _model, _pk):
        return self._image

    async def execute(self, _stmt, _params=None):
        # #2400 — the catalogue advisory lock; nothing to lock here.
        return None


# ── resolve_slot_image_target ────────────────────────────────────────


@pytest.mark.asyncio
async def test_external_url_carries_no_hash_and_verifies_tls() -> None:
    target = await resolve_slot_image_target(
        _FakeDB(), base_url="https://cp.local/", slot_image_url="https://github.com/x.raw.xz"
    )
    assert target == SlotImageTarget(
        url="https://github.com/x.raw.xz", sha256=None, tls_insecure=False
    )


@pytest.mark.asyncio
async def test_uploaded_image_carries_hash_and_relaxes_tls() -> None:
    """Self-served bytes sit behind the appliance's own self-signed cert,
    so the runner needs the hash to verify against AND permission to skip
    cert-verify for that fetch (#386)."""
    image_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
    image = SimpleNamespace(id=image_id, sha256="ab" * 32, architecture=None)

    target = await resolve_slot_image_target(
        _FakeDB(image), base_url="https://cp.local/", slot_image_id=image_id
    )

    assert target.sha256 == "ab" * 32
    assert target.tls_insecure is True
    assert target.url.startswith(
        f"https://cp.local/api/v1/appliance/upgrade-images/{image_id}/raw.xz?t="
    )
    token = target.url.split("?t=")[1]
    assert len(token) == 64
    assert all(c in "0123456789abcdef" for c in token)


@pytest.mark.asyncio
async def test_missing_image_row_raises() -> None:
    with pytest.raises(SlotImageResolutionError, match="not found"):
        await resolve_slot_image_target(
            _FakeDB(None), base_url="https://cp.local/", slot_image_id=uuid.uuid4()
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"slot_image_id": uuid.uuid4(), "slot_image_url": "https://x/y.raw.xz"},
    ],
    ids=["neither", "both"],
)
async def test_exactly_one_source_required(kwargs) -> None:
    with pytest.raises(SlotImageResolutionError, match="exactly one"):
        await resolve_slot_image_target(_FakeDB(), base_url="https://cp.local/", **kwargs)


# ── stamp_desired_slot_image ─────────────────────────────────────────


def test_stamp_writes_all_four_columns() -> None:
    row = _fake_appliance()
    target = SlotImageTarget(url="https://cp.local/x.raw.xz", sha256="cd" * 32, tls_insecure=True)

    stamp_desired_slot_image(row, target, desired_version="2026.07.30-1")

    assert row.desired_appliance_version == "2026.07.30-1"
    assert row.desired_slot_image_url == "https://cp.local/x.raw.xz"
    assert row.desired_slot_image_sha256 == "cd" * 32
    assert row.desired_slot_image_tls_insecure is True


def test_stamp_clears_stale_integrity_hints() -> None:
    """Re-scheduling with an external URL must not leave the previous
    upload's hash behind — the runner would check the new bytes against
    the old digest and fail the apply as corruption."""
    row = _fake_appliance()
    row.desired_slot_image_sha256 = "ab" * 32
    row.desired_slot_image_tls_insecure = True

    stamp_desired_slot_image(
        row, SlotImageTarget(url="https://github.com/y.raw.xz"), desired_version="2026.07.30-1"
    )

    assert row.desired_slot_image_sha256 is None
    assert row.desired_slot_image_tls_insecure is False


def test_stamp_adds_refire_nonce_for_a_capable_runner() -> None:
    row = _fake_appliance(supervisor_version="2026.07.30-1")
    stamp_desired_slot_image(
        row,
        SlotImageTarget(url="https://cp.local/x.raw.xz", nonce="abc123"),
        desired_version="2026.07.30-1",
    )
    assert row.desired_slot_image_url == "https://cp.local/x.raw.xz#a=abc123"


def test_restamping_the_same_target_reproduces_the_same_url() -> None:
    """An orchestrator resume re-drives an incomplete node from step 1. If
    the nonce were minted per stamp the node would get a URL it has never
    fired and re-run a full slot apply of an image it already staged."""
    target = SlotImageTarget(url="https://cp.local/x.raw.xz", nonce="stable99")
    first, second = _fake_appliance(supervisor_version="2026.07.30-1"), _fake_appliance(
        supervisor_version="2026.07.30-1"
    )
    stamp_desired_slot_image(first, target, desired_version="2026.07.30-1")
    stamp_desired_slot_image(second, target, desired_version="2026.07.30-1")
    assert first.desired_slot_image_url == second.desired_slot_image_url


def test_stamp_omits_nonce_when_the_target_carries_none() -> None:
    row = _fake_appliance(supervisor_version="2026.07.30-1")
    stamp_desired_slot_image(
        row, SlotImageTarget(url="https://cp.local/x.raw.xz"), desired_version="2026.07.30-1"
    )
    assert row.desired_slot_image_url == "https://cp.local/x.raw.xz"


def test_stamp_omits_nonce_for_a_pre_386_runner() -> None:
    """An older runner passes the fragment straight to the downloader and
    the apply wedges at in-flight forever (#419)."""
    row = _fake_appliance(supervisor_version="2026.06.11-1")
    stamp_desired_slot_image(
        row,
        SlotImageTarget(url="https://cp.local/x.raw.xz", nonce="abc123"),
        desired_version="2026.07.30-1",
    )
    assert row.desired_slot_image_url == "https://cp.local/x.raw.xz"


# ── plan round-trip ──────────────────────────────────────────────────


def test_plan_fields_round_trip() -> None:
    target = SlotImageTarget(url="https://cp.local/x.raw.xz", sha256="ef" * 32, tls_insecure=True)
    assert SlotImageTarget.from_plan_fields(target.as_plan_fields()) == target


def test_plan_fields_tolerate_a_pre_787_plan() -> None:
    """Runs planned before the integrity fields existed still resolve —
    to exactly the url-only target they had at plan time."""
    target = SlotImageTarget.from_plan_fields({"slot_image_url": "https://cp.local/x.raw.xz"})
    assert target == SlotImageTarget(
        url="https://cp.local/x.raw.xz", sha256=None, tls_insecure=False
    )
