"""The seeder's bulk record load rides out a retryable answer (#2879).

On 2026-10-27 one ``records/bulk-create`` batch was answered 503, the API's
"A backend dependency did not answer in time (database failover or restart
in progress). Retry." with ``Retry-After: 2``. ``_BulkLoader`` counted all
1000 of its records failed, which put the seed past its max(10, 1%) bound:
rc 3, and the load lane's latency and DHCP rows went red with it.

These tests drive the real ``ApiClient`` and ``_BulkLoader`` over httpx's
MockTransport, against a fake bulk-create that keeps the endpoint's own
contract: a record the zone already holds is skipped, never stored twice
(#1230). No network, no appliance, no real waits.

httpx is imported, never import-skipped: the Perf — Tests job installs it
for this file, and a skip here would let a reverted fix pass green (the
trap the review of #1063 found).
"""

from __future__ import annotations

import email.utils
import json
import logging
import re
import sys
import threading
import time
import uuid
from pathlib import Path

import httpx
import pytest
import yaml

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))  # perf/seeder: seed_scaffold, _api
sys.path.insert(0, str(HERE.parents[2] / "harness"))  # spddi_perf

import seed_scaffold as ss  # noqa: E402
import spddi_perf.manifest as manifest_mod  # noqa: E402
from _api import ApiClient  # noqa: E402
from spddi_perf.runpaths import RunPaths  # noqa: E402

SMOKE = HERE.parents[2] / "manifests" / "smoke.yaml"
GROUP = "6f1d0d4e-0000-4000-8000-000000000001"
ZONE = "6f1d0d4e-0000-4000-8000-0000000000f1"
BULK = re.compile(r"/api/v1/dns/groups/[^/]+/zones/(?P<zone>[^/]+)/records/bulk-create$")
ONE = re.compile(r"/api/v1/dns/groups/[^/]+/zones/(?P<zone>[^/]+)/records$")
BODIES = {
    # backend/app/main.py: the handler for a dependency that did not answer in time
    503: "A backend dependency did not answer in time "
    "(database failover or restart in progress). Retry.",
    # frontend/default.conf.template, @api_unavailable
    502: "The api is not reachable right now; retry shortly.",
    504: "The api did not answer in time; retry shortly.",
}


class FakeAppliance:
    """records/bulk-create and the singular records POST over a record store.

    ``faults`` answers the next bulk-create calls, one entry per call, in
    order: ``None`` answers normally, ``(status, retry_after, lands)``
    answers ``status``. ``lands`` stores the batch first: nginx's 502/504
    can come after the api committed. ``fail_always`` answers every
    bulk-create call with ``(status, retry_after)``.
    """

    def __init__(self, faults=(), *, fail_always=None, bulk_404=False):
        self.faults = list(faults)
        self.fail_always = fail_always
        self.bulk_404 = bulk_404
        self.zones: dict[str, list[tuple[str, str, str]]] = {}
        self.bulk_calls = 0
        self.single_calls = 0
        self._lock = threading.Lock()

    def _store(self, zone, records):
        rows = self.zones.setdefault(zone, [])
        held = {(n.lower(), t.upper(), v.strip()) for n, t, v in rows}
        created, skipped = 0, []
        for r in records:
            key = (r["name"].lower(), r["record_type"].upper(), r["value"].strip())
            if key in held:
                skipped.append({**r, "reason": "identical record already exists"})
                continue
            held.add(key)
            rows.append((r["name"], r["record_type"], r["value"]))
            created += 1
        return created, skipped

    @staticmethod
    def _error(status, retry_after):
        headers = {} if retry_after is None else {"Retry-After": retry_after}
        detail = BODIES.get(status, f"refused with {status}")
        return httpx.Response(status, json={"detail": detail}, headers=headers)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        with self._lock:
            bulk = BULK.search(path)
            if bulk:
                self.bulk_calls += 1
                if self.bulk_404:
                    return httpx.Response(404, json={"detail": "Not Found"})
                records = json.loads(request.content)["records"]
                if self.fail_always is not None:
                    return self._error(*self.fail_always)
                fault = self.faults.pop(0) if self.faults else None
                if fault is not None:
                    status, retry_after, lands = fault
                    if lands:
                        self._store(bulk["zone"], records)
                    return self._error(status, retry_after)
                created, skipped = self._store(bulk["zone"], records)
                body = {"created": created, "skipped": skipped, "target_serial": 1}
                return httpx.Response(201, json=body)
            one = ONE.search(path)
            if one:
                self.single_calls += 1
                self._store(one["zone"], [json.loads(request.content)])
                return httpx.Response(201, json={"id": str(uuid.uuid4())})
            # The scaffold's other creates (space, block, groups, zones,
            # subnets, scopes, pools): an id is all the seeder reads back.
            body = json.loads(request.content) if request.content else {}
            reply = {"id": str(uuid.uuid4()), "name": body.get("name", "")}
            reply["network"] = body.get("network", "")
            return httpx.Response(201, json=reply)


def mocked(api: ApiClient, app: FakeAppliance) -> ApiClient:
    api._client.close()
    api._client = httpx.Client(base_url=api.base_url, transport=httpx.MockTransport(app.handler))
    return api


class Events(logging.Handler):
    """The loader's structured events, by message."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def named(self, message: str) -> list[dict]:
        return [getattr(r, "fields", {}) for r in self.records if r.getMessage() == message]


@pytest.fixture
def events():
    handler = Events()
    log = logging.getLogger("test.seeder.bulk_create_retry")
    log.handlers[:] = [handler]
    log.setLevel(logging.DEBUG)
    log.propagate = False
    return log, handler


def loader_for(app: FakeAppliance, log: logging.Logger):
    api = mocked(ApiClient("https://appliance.test/api", "test-token", run_id="t2879"), app)
    loader = ss._BulkLoader(api, log, GROUP)
    waits: list[float] = []
    loader._sleep = waits.append  # no real waits; what was asked is recorded
    return loader, waits


def items(n: int) -> list[tuple[str, dict]]:
    return [
        (
            ZONE,
            {"name": f"dev-{i:07d}", "record_type": "A", "value": f"10.0.{i // 250}.{i % 250 + 1}"},
        )
        for i in range(n)
    ]


# --- The contract: a retryable answer is sent again, not counted failed ----


@pytest.mark.parametrize(
    "status, retry_after, least, most",
    [
        (503, "2", 2.0, 2.5),  # the API's own answer: the failure in #2879
        (502, "2", 2.0, 2.5),  # nginx: no api endpoint ready
        (503, None, 1.0, 1.25),  # no Retry-After: the first backoff step
        (504, "2", 30.0, 37.5),  # nginx stopped waiting; the api may still commit
    ],
)
def test_a_retryable_answer_then_success_counts_the_batch_created(
    status, retry_after, least, most, events
):
    log, ev = events
    app = FakeAppliance([(status, retry_after, False)])
    loader, waits = loader_for(app, log)

    loader.load(items(1000))

    assert (loader.created, loader.failed) == (1000, 0)
    assert app.bulk_calls == 2
    assert len(app.zones[ZONE]) == 1000
    assert len(waits) == 1 and least <= waits[0] <= most
    assert (loader.retries, loader.batches_retried) == (1, 1)
    assert loader.retries_by_status == {str(status): 1}
    (retry,) = ev.named("bulk_create_retry")
    assert (retry["status"], retry["attempt"], retry["retry_after"]) == (status, 1, retry_after)
    assert retry["wait_s"] == round(waits[0], 2)
    assert retry["path"] == f"/v1/dns/groups/{GROUP}/zones/{ZONE}/records/bulk-create"
    (recovered,) = ev.named("bulk_create_recovered")
    assert (recovered["attempts"], recovered["created"]) == (2, 1000)


@pytest.mark.parametrize("status", [502, 504])
def test_a_batch_that_landed_before_its_answer_was_lost_is_neither_failed_nor_doubled(
    status, events
):
    log, ev = events
    app = FakeAppliance([(status, "2", True)])
    loader, _ = loader_for(app, log)

    loader.load(items(1000))

    assert loader.failed == 0
    assert loader.created == 0  # the resend created nothing ...
    assert loader.already_present == 1000  # ... because the first send's records are there
    assert len(app.zones[ZONE]) == 1000  # once each
    (recovered,) = ev.named("bulk_create_recovered")
    assert recovered["already_present"] == 1000


def test_a_batch_that_never_recovers_counts_failed_within_the_bounds(events):
    log, ev = events
    app = FakeAppliance(fail_always=(503, "2"))
    loader, waits = loader_for(app, log)

    loader.load(items(1000))

    assert (loader.created, loader.failed) == (0, 1000)
    assert app.bulk_calls == ss.BULK_MAX_ATTEMPTS
    assert len(waits) == ss.BULK_MAX_ATTEMPTS - 1 == loader.retries
    assert sum(waits) <= ss.BULK_RETRY_BUDGET_S
    (gave_up,) = ev.named("bulk_create_gave_up")
    assert (gave_up["status"], gave_up["attempts"]) == (503, ss.BULK_MAX_ATTEMPTS)
    assert "-> 503:" in loader._first_errors[0]


def test_retry_after_is_capped_and_the_wait_per_batch_is_bounded(events):
    log, _ = events
    app = FakeAppliance(fail_always=(504, "3600"))
    loader, waits = loader_for(app, log)

    loader.load(items(1000))

    assert loader.failed == 1000
    assert waits and all(w <= ss.BULK_RETRY_AFTER_CAP_S * 1.25 for w in waits)
    assert sum(waits) <= ss.BULK_RETRY_BUDGET_S
    assert app.bulk_calls == len(waits) + 1


def test_retry_after_reads_seconds_and_http_dates():
    assert ss._retry_after_s("2") == 2.0
    assert ss._retry_after_s(" 7 ") == 7.0
    assert ss._retry_after_s(None) is None
    assert ss._retry_after_s("") is None
    assert ss._retry_after_s("soon") is None
    assert ss._retry_after_s("-5") == 0.0
    assert ss._retry_after_s("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0
    later = email.utils.formatdate(time.time() + 90, usegmt=True)
    assert 80.0 <= ss._retry_after_s(later) <= 91.0


# --- What the change keeps ------------------------------------------------


@pytest.mark.parametrize("status", [400, 409, 422, 500])
def test_a_non_retryable_answer_still_counts_the_batch_failed_at_once(status, events):
    log, _ = events
    app = FakeAppliance([(status, None, False)])
    loader, waits = loader_for(app, log)

    loader.load(items(1000))

    assert (loader.created, loader.failed) == (0, 1000)
    assert app.bulk_calls == 1 and waits == []
    assert f"-> {status}:" in loader._first_errors[0]


@pytest.mark.parametrize("status", [401, 403])
def test_an_auth_failure_still_aborts_the_load_without_a_retry(status, events):
    log, ev = events
    app = FakeAppliance([(status, None, False)])
    loader, waits = loader_for(app, log)

    loader.load(items(1000))

    assert loader.aborted is True
    assert loader.failed == 1000
    assert app.bulk_calls == 1 and waits == []
    assert len(ev.named("bulk_load_auth_abort")) == 1


def test_a_404_still_falls_back_to_the_per_record_path(events):
    log, _ = events
    app = FakeAppliance(bulk_404=True)
    loader, waits = loader_for(app, log)

    loader.load(items(300))

    assert (app.bulk_calls, app.single_calls) == (1, 300)
    assert (loader.created, loader.failed) == (300, 0)
    assert waits == []


# --- End to end: the seed's exit code and manifest ------------------------


def test_the_seed_exits_0_and_records_the_retry_when_one_batch_needed_it(tmp_path, monkeypatch):
    data = yaml.safe_load(SMOKE.read_text())
    data["seed"]["ip_block"] = "10.0.0.0/16"
    data["seed"]["subnets"].update(count=1, prefix=20)
    data["seed"]["dns"]["authoritative_records"] = 1500  # 3000 records, four batches
    m = manifest_mod.from_dict(data)
    # The probe batch goes through; the next batch sent is answered 503.
    app = FakeAppliance([None, (503, "2", False)])

    class MockedApiClient(ApiClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            mocked(self, app)

    monkeypatch.setattr(ss, "ApiClient", MockedApiClient)
    monkeypatch.setenv(m.observability.superadmin_token_env, "test-token")
    monkeypatch.setattr(ss.time, "sleep", lambda s: None)  # no real waits
    rp = RunPaths.for_run("t2879-run", tmp_path)
    rp.ensure_dirs()

    rc = ss.run(rp, m, logging.getLogger("test.seeder.bulk_create_retry.run"))

    seeded = json.loads(Path(rp.seed_manifest).read_text())["authoritative_records"]
    assert rc == 0
    assert (seeded["planned"], seeded["created"], seeded["failed"]) == (3000, 3000, 0)
    assert (seeded["retries"], seeded["retries_by_status"]) == (1, {"503": 1})
    assert seeded["batches_retried"] == 1 and seeded["already_present"] == 0
    assert sum(len(rows) for rows in app.zones.values()) == 3000
