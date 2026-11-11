"""The DHCP unstick hook deletes only stuck pods of the release's DHCP StatefulSets (#3907).

``charts/spatiumddi/files/dhcp-unstick-pods.py`` is what the chart's
pre-upgrade hook runs. Lives in ``appliance/tests`` because that is the
hermetic pytest job that runs on every PR (see test_redis_sentinel_render_config).

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_dhcp_unstick_pods.py -v
"""

from __future__ import annotations

import datetime as dt
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "charts" / "spatiumddi" / "files" / "dhcp-unstick-pods.py"
spec = importlib.util.spec_from_file_location("dhcp_unstick", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

NOW = dt.datetime(2026, 11, 11, 12, 0, 0, tzinfo=dt.timezone.utc)
SELECTOR = "app.kubernetes.io/instance=r,app.kubernetes.io/component=dhcp-agent"


def ts(seconds_ago):
    return (NOW - dt.timedelta(seconds=seconds_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def pod(name, owner, ready, age=600, phase="Running"):
    return {
        "metadata": {
            "name": name,
            "ownerReferences": [{"kind": "StatefulSet", "name": owner}],
        },
        "status": {
            "phase": phase,
            "startTime": ts(age),
            "conditions": [
                {
                    "type": "Ready",
                    "status": "True" if ready else "False",
                    "lastTransitionTime": ts(age),
                }
            ],
        },
    }


def sts(name):
    return {
        "metadata": {"name": name},
        "spec": {"selector": {"matchLabels": {"app.kubernetes.io/instance-name": name}}},
    }


class FakeApi:
    def __init__(self, stss, pods):
        self.stss, self.pods = stss, pods
        self.calls = []

    def __call__(self, method, path, query=None):
        self.calls.append((method, path, query))
        if method == "DELETE":
            return {}
        if path.endswith("/statefulsets"):
            # The API filters by label; the script must ask for the release's DHCP agents.
            assert query == {"labelSelector": SELECTOR}
            return {"items": self.stss}
        name = query["labelSelector"].split("=", 1)[1]
        return {"items": self.pods.get(name, [])}

    def deleted(self):
        return [p.rsplit("/", 1)[1] for m, p, _ in self.calls if m == "DELETE"]


def test_deletes_only_the_unready_pod_and_leaves_ready_ones():
    api = FakeApi(
        [sts("dhcp-kea-a"), sts("dhcp-kea-b")],
        {
            "dhcp-kea-a": [pod("dhcp-kea-a-0", "dhcp-kea-a", ready=False)],
            "dhcp-kea-b": [pod("dhcp-kea-b-0", "dhcp-kea-b", ready=True)],
        },
    )
    mod.run(api, "ns", SELECTOR, 120, NOW)
    assert api.deleted() == ["dhcp-kea-a-0"]


def test_a_recently_unready_or_not_running_pod_is_left_alone():
    api = FakeApi(
        [sts("dhcp-kea-a")],
        {
            "dhcp-kea-a": [
                pod("fresh", "dhcp-kea-a", ready=False, age=30),
                pod("pending", "dhcp-kea-a", ready=False, phase="Pending"),
            ]
        },
    )
    mod.run(api, "ns", SELECTOR, 120, NOW)
    assert api.deleted() == []


def test_a_pod_not_owned_by_the_statefulset_is_left_alone():
    api = FakeApi(
        [sts("dhcp-kea-a")],
        {"dhcp-kea-a": [pod("stray", "someone-else", ready=False)]},
    )
    mod.run(api, "ns", SELECTOR, 120, NOW)
    assert api.deleted() == []


def test_no_statefulsets_means_no_pod_listing_and_no_delete():
    api = FakeApi([], {})
    assert mod.run(api, "ns", SELECTOR, 120, NOW) == []
    assert [m for m, _, _ in api.calls] == ["GET"]


def test_a_pod_with_no_ready_condition_uses_its_start_time():
    p = pod("dhcp-kea-a-0", "dhcp-kea-a", ready=False, age=900)
    p["status"]["conditions"] = []
    api = FakeApi([sts("dhcp-kea-a")], {"dhcp-kea-a": [p]})
    mod.run(api, "ns", SELECTOR, 120, NOW)
    assert api.deleted() == ["dhcp-kea-a-0"]
