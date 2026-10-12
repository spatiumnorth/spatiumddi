"""The audit chain survives the JSONB round trip (GHSA-8288-8vg9-82gr, #1615).

``compute_audit_hashes`` hashes ``old_value`` / ``new_value`` /
``changed_fields`` before the INSERT; ``verify_chain`` re-hashes what
PostgreSQL hands back. JSONB stores numbers as ``numeric``, so it does not
return every float as it was sent: ``1e16`` comes back as the integer
``10000000000000000`` and ``-0.0`` as ``0.0``. Before the fix an honest row
carrying such a value (a fuzzed ``tags`` / ``custom_fields`` entry is
enough) reported ``row_hash_mismatch`` forever.

These tests go through the real session and a fresh read, because the
in-memory objects of the writing session would hide exactly the drift
being tested.
"""

from __future__ import annotations

import json
import math
import random
import uuid

import pytest
from sqlalchemy import text

from app.db import AsyncSessionLocal
from app.models.audit import AuditLog
from app.services.audit_chain import normalise_jsonb_value, verify_chain

pytestmark = pytest.mark.asyncio

_PROBLEM_FLOATS = {
    "big": 1e16,
    "big_mantissa": 1.2345678901234568e17,
    "huge": 1e300,
    "neg_zero": -0.0,
    "neg_big": -3.5e20,
    "small": 1.5e-07,
    "tiny": 5e-324,
    "plain": 1.0,
    "pi": 3.141592653589793,
}


def _row(**values: object) -> AuditLog:
    return AuditLog(
        user_display_name="chain-probe",
        action="create",
        resource_type="customer",
        resource_id=str(uuid.uuid4()),
        resource_display="chain-probe",
        **values,
    )


async def _insert(row: AuditLog) -> None:
    async with AsyncSessionLocal() as session:
        session.add(row)
        await session.commit()


async def _verify() -> object:
    async with AsyncSessionLocal() as session:
        return await verify_chain(session)


async def test_floats_jsonb_rewrites_still_verify() -> None:
    await _insert(
        _row(
            new_value={
                "name": "chain-probe",
                "tags": dict(_PROBLEM_FLOATS),
                "custom_fields": {"nested": [1e16, {"z": -0.0}, [2.5e18]]},
            },
            old_value={"n": 1e16},
            changed_fields=["tags", "custom_fields"],
        )
    )
    await _insert(_row(new_value={"after": 1}))

    result = await _verify()
    assert result.ok, result.breaks
    assert result.rows_checked == 2


async def test_nan_and_infinity_do_not_break_the_write_or_the_chain() -> None:
    # JSONB rejects NaN / Infinity outright, so before the fix this INSERT
    # failed — and took the audited mutation down with it.
    await _insert(
        _row(new_value={"nan": math.nan, "inf": math.inf, "ninf": -math.inf, "deep": [math.nan]})
    )
    async with AsyncSessionLocal() as session:
        stored = (
            await session.execute(text("SELECT new_value::text FROM audit_log ORDER BY seq DESC"))
        ).scalar_one()
    assert json.loads(stored) == {
        "nan": "NaN",
        "inf": "Infinity",
        "ninf": "-Infinity",
        "deep": ["NaN"],
    }
    result = await _verify()
    assert result.ok, result.breaks


async def test_normaliser_matches_a_real_jsonb_round_trip() -> None:
    rng = random.Random(1615)
    samples: list[object] = list(_PROBLEM_FLOATS.values())
    for _ in range(400):
        samples.append(rng.uniform(-1, 1) * 10 ** rng.randint(-330, 308))
    samples += [rng.random() for _ in range(50)]
    samples += [10**30, -(10**19), 0, True, None, "x\u0001y", {"k": [1e16, "s"]}]

    async with AsyncSessionLocal() as session:
        for value in samples:
            sent = json.dumps(value)
            back = json.loads(
                (
                    await session.execute(text("SELECT CAST(:t AS jsonb)::text"), {"t": sent})
                ).scalar_one()
            )
            ours = normalise_jsonb_value(value)
            assert json.dumps(ours, sort_keys=True) == json.dumps(back, sort_keys=True), (
                value,
                ours,
                back,
            )


async def test_break_names_the_row() -> None:
    row = _row(new_value={"a": 1})
    await _insert(row)
    async with AsyncSessionLocal() as session:
        await session.execute(
            text("UPDATE audit_log SET resource_display = 'edited' WHERE id = :id"),
            {"id": row.id},
        )
        await session.commit()

    result = await _verify()
    assert not result.ok
    brk = result.breaks[0]
    assert brk.reason == "row_hash_mismatch"
    assert brk.action == "create"
    assert brk.resource_type == "customer"
    assert brk.resource_id == row.resource_id
