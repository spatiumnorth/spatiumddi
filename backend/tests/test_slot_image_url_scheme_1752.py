"""#1752 — a slot image URL the supervisor refuses must be refused at plan time.

The supervisor accepts only ``https://`` / ``file://`` (#242) and refuses
anything else with a warning log and no trigger, so an ``http://`` Plan
started and every node's stage step waited out its whole timeout.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.api.v1.upgrades import PlanRequest
from app.services.appliance.slot_image_target import (
    SUPERVISOR_ALLOWED_URL_SCHEMES,
    SlotImageResolutionError,
    resolve_slot_image_target,
    slot_image_url_problem,
)

_SUPERVISOR = (
    Path(__file__).resolve().parents[2] / "agent/supervisor/spatium_supervisor/appliance_state.py"
)


def test_plan_rejects_http_url() -> None:
    with pytest.raises(ValidationError) as exc:
        PlanRequest(target_version="2026.10.13-1", slot_image_url="http://10.0.0.5:9/x.raw.xz")
    assert "https://" in str(exc.value)
    assert "http://" in str(exc.value)


def test_plan_accepts_https_url() -> None:
    assert PlanRequest(
        target_version="2026.10.13-1", slot_image_url="https://mirror.example/x.raw.xz"
    ).slot_image_url


def test_plan_rejects_other_schemes_and_hostless() -> None:
    for bad in ("ftp://h/x", "s3://b/x", "https:///x", "mirror/x.raw.xz"):
        with pytest.raises(ValidationError):
            PlanRequest(target_version="2026.10.13-1", slot_image_url=bad)


@pytest.mark.asyncio
async def test_resolver_chokepoint_refuses_http_for_every_scheduler() -> None:
    # The per-appliance schedule and the rolling orchestrator both resolve
    # through here; neither had a scheme check of its own.
    with pytest.raises(SlotImageResolutionError, match="https://"):
        await resolve_slot_image_target(
            None, base_url="https://cp/", slot_image_url="http://mirror/x.raw.xz"  # type: ignore[arg-type]
        )
    target = await resolve_slot_image_target(
        None, base_url="https://cp/", slot_image_url="https://mirror/x.raw.xz"  # type: ignore[arg-type]
    )
    assert target.url == "https://mirror/x.raw.xz"


@pytest.mark.skipif(not _SUPERVISOR.exists(), reason="agent/ is not in the dev image")
def test_rule_matches_the_supervisors_allowed_schemes() -> None:
    src = _SUPERVISOR.read_text(encoding="utf-8")
    m = re.search(r"allowed_schemes = \(([^)]*)\)", src)
    assert m, "supervisor allowed_schemes tuple moved; update this parity test"
    sup = {s.strip().strip("\"'").removesuffix("://") for s in m.group(1).split(",") if s.strip()}
    assert sup == set(SUPERVISOR_ALLOWED_URL_SCHEMES)


def test_fragment_nonce_is_ignored() -> None:
    assert slot_image_url_problem("https://h/x.raw.xz#a=abc") is None
    assert slot_image_url_problem("HTTP://h/x#a=abc") is not None


def test_rule_mirrors_the_supervisors_prefix_test() -> None:
    # The supervisor tests ``startswith("https://" | "file://")`` on the
    # stripped URL, not a parsed scheme: ``file:/x`` parses as ``file`` and
    # is still refused there, so it must be refused here too.
    assert slot_image_url_problem("file:///var/lib/x.raw.xz") is None
    assert slot_image_url_problem("  https://h/x.raw.xz  ") is None
    assert slot_image_url_problem("file:/var/lib/x.raw.xz") is not None
    assert slot_image_url_problem("https:h/x.raw.xz") is not None
    assert PlanRequest(
        target_version="2026.10.13-1", slot_image_url="file:///var/lib/x.raw.xz"
    ).slot_image_url
