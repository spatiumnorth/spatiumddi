"""A per-node write rides out a transient kubeapi answer (#2449).

Found by ddi-pg's QA of spatiumddi#2388's rolling walk: a three-node Rolling
Upgrade failed with ``node ddipg-member-3 failed at step cnpg_maintenance_on:
kubeapi status 500: ...failed calling webhook "mcluster.cnpg.io"...``. The
step PATCHes the CNPG Cluster once; CloudNativePG's mutating webhook was briefly
between endpoints (its operator pod had rescheduled off a cordoned node), so the
API server answered 500, and the single try failed the whole run.

``_run_step_riding_db_failover`` already retries a step that *raised* a transient
database error (#2177). It did not retry a step that *returned* a failed result,
which is how the kubeapi helpers report a 500 (``k8s.py`` catches the socket
error and the HTTP status into ``(False, "kubeapi ...")``). The fix tries the
idempotent writes again, within a budget, for a transient kubeapi answer only.

* cnpg_maintenance_on rides out a transient 500/408/409/429 and a socket error,
  and succeeds when it clears.
* An answer that never clears fails the step once the budget is spent, with the
  server's own error, as before.
* A permission refusal, a sub-500 status, a non-kubeapi error, and a transient
  answer at a step that is not an idempotent write are not retried.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.services.upgrades import per_node

# The shape spatiumddi#2449's node saw (truncated as the k8s helper truncates).
WEBHOOK_500 = (
    'kubeapi status 500: b\'{"status":"Failure","message":"Internal error '
    'occurred: failed calling webhook \\"mcluster.cnpg.io\\": failed to call '
    "webhook: Post ...'"
)
SOCKET_ERR = "kubeapi PATCH /api/v1/nodes/ddipg-member-3: [Errno 111] Connection refused"


def _fake_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """A monotonic clock the step's own sleep advances, so the retry budget is
    spent without real time passing (the #2177 tests' pattern)."""
    now = [0.0]

    async def _sleep(delay_s: float) -> None:
        now[0] += delay_s

    monkeypatch.setattr(per_node, "_db_retry_sleep", _sleep, raising=False)
    monkeypatch.setattr(per_node, "_db_retry_clock", lambda: now[0], raising=False)
    return now


def _answers(step: str, errors: list[str | None], calls: list[str]):
    """A ``make`` that returns one StepResult per call from ``errors`` (None =
    ok), then ok once the list is spent. Records each call."""

    async def make() -> per_node.StepResult:
        i = len(calls)
        calls.append(step)
        err = errors[i] if i < len(errors) else None
        return per_node.StepResult(name=step, started_at="t").finish(err is None, error=err)

    return make


async def _run(
    step: str,
    errors: list[str | None],
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[per_node.StepResult, list[str]]:
    _fake_clock(monkeypatch)
    calls: list[str] = []
    result = await per_node._run_step_riding_db_failover(
        AsyncMock(), step, "ddipg-member-3", _answers(step, errors, calls)
    )
    return result, calls


# ── the defect: cnpg_maintenance_on rides out the webhook 500 ────────────────


async def test_cnpg_maintenance_on_retries_the_webhook_500_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, calls = await _run("cnpg_maintenance_on", [WEBHOOK_500] * 3, monkeypatch)
    assert result.ok is True
    assert len(calls) == 4  # three 500s ridden out, then the window is set


async def test_a_socket_error_is_also_ridden_out(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = await _run("cnpg_maintenance_on", [SOCKET_ERR, SOCKET_ERR], monkeypatch)
    assert result.ok is True
    assert len(calls) == 3


async def test_an_answer_that_never_clears_fails_with_its_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Always 500: retried until the budget is spent, then returned as it was.
    result, calls = await _run("cnpg_maintenance_on", [WEBHOOK_500] * 100, monkeypatch)
    assert result.ok is False
    assert result.error == WEBHOOK_500
    assert len(calls) > 2  # it was tried again and again, not failed at the first


# ── scope: only the idempotent writes, only a transient kubeapi answer ───────


@pytest.mark.parametrize(
    "error",
    [
        "ServiceAccount not mounted",
        "kubeapi status 403: b'forbidden'",
        "kubeapi status 404: b'not found'",
        "kubeapi status 422: b'invalid'",
        "rbac forbidden",
        "step crashed: boom",
        None,
    ],
)
async def test_cnpg_maintenance_on_does_not_retry_a_non_transient_answer(
    error: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # None here means "ok on the first call"; the others fail once and stay.
    result, calls = await _run("cnpg_maintenance_on", [error], monkeypatch)
    assert len(calls) == 1
    assert result.ok is (error is None)


@pytest.mark.parametrize("step", ["health_gate", "drain", "stage", "cluster_verify"])
async def test_a_transient_500_at_a_non_write_step_is_not_retried(
    step: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, calls = await _run(step, [WEBHOOK_500], monkeypatch)
    assert len(calls) == 1  # out of KUBEAPI_RETRY_STEPS: failed at the first try
    assert result.ok is False


# ── the classifier ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("error", "transient"),
    [
        (WEBHOOK_500, True),
        (SOCKET_ERR, True),
        ("kubeapi status 503: b'unavailable'", True),
        ("kubeapi status 408: b'timeout'", True),
        ("kubeapi status 409: b'conflict'", True),
        ("kubeapi status 429: b'slow down'", True),
        ("kubeapi status 403: b'forbidden'", False),
        ("kubeapi status 404: b'gone'", False),
        ("kubeapi status 422: b'invalid'", False),
        ("ServiceAccount not mounted", False),
        ("rbac forbidden", False),
        ("step crashed: InterfaceError", False),
        ("", False),
        (None, False),
    ],
)
def test_kubeapi_transient_classification(error: str | None, transient: bool) -> None:
    assert per_node._kubeapi_transient(error) is transient


def test_the_retry_steps_are_the_idempotent_writes() -> None:
    # The write step that holds the node's maintenance window; never a read or a wait.
    assert per_node.KUBEAPI_RETRY_STEPS == frozenset({"cnpg_maintenance_on"})
