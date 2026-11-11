"""Delete the stuck, never-Ready pods of this release's DHCP agent StatefulSets (#3907).

Run by the ``pre-upgrade`` hook in templates/dhcp-agent-unstick.yaml, stdlib
only. A StatefulSet with ``OrderedReady`` + ``RollingUpdate`` will not replace a
pod that is not Ready, so a pod that was never Ready on the old release (the
old readiness probe could never pass) keeps the new image from ever rolling
out. Deleting such a pod lets the controller recreate it from the new revision.

Only a pod that is Running, not Ready, and has been not Ready for at least
MIN_UNREADY_SECONDS is deleted, and only if a StatefulSet carrying the
release's DHCP agent labels owns it. A Ready pod is never touched. Best
effort: any error is logged and the hook still exits 0, so this can never be
the reason an upgrade fails.
"""

import datetime
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

SA = "/var/run/secrets/kubernetes.io/serviceaccount/"


def _parse_time(value):
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
    except (TypeError, ValueError):
        return None


def unready_seconds(pod, now):
    """Seconds the pod has been Running-but-not-Ready; None if it is not that."""
    status = pod.get("status") or {}
    if status.get("phase") != "Running":
        return None
    ready = None
    for cond in status.get("conditions") or []:
        if cond.get("type") == "Ready":
            ready = cond
    if ready is not None and ready.get("status") == "True":
        return None
    since = _parse_time((ready or {}).get("lastTransitionTime")) or _parse_time(
        status.get("startTime")
    )
    if since is None:
        return None
    return (now - since).total_seconds()


def select_stuck_pods(statefulsets, pods_by_sts, now, min_unready):
    """[(statefulset name, pod name)] for the pods that should be deleted."""
    out = []
    for sts in statefulsets:
        name = sts["metadata"]["name"]
        for pod in pods_by_sts.get(name, []):
            owned = any(
                o.get("kind") == "StatefulSet" and o.get("name") == name
                for o in (pod["metadata"].get("ownerReferences") or [])
            )
            age = unready_seconds(pod, now)
            if owned and age is not None and age >= min_unready:
                out.append((name, pod["metadata"]["name"]))
    return out


def run(call, ns, selector, min_unready, now):
    stss = call("GET", f"/apis/apps/v1/namespaces/{ns}/statefulsets", {"labelSelector": selector})[
        "items"
    ]
    pods_by_sts = {}
    for sts in stss:
        match = (sts["spec"].get("selector") or {}).get("matchLabels") or {}
        if not match:
            continue
        sel = ",".join(f"{k}={v}" for k, v in sorted(match.items()))
        pods_by_sts[sts["metadata"]["name"]] = call(
            "GET", f"/api/v1/namespaces/{ns}/pods", {"labelSelector": sel}
        )["items"]
    stuck = select_stuck_pods(stss, pods_by_sts, now, min_unready)
    for sts_name, pod_name in stuck:
        print(f"dhcp-unstick: deleting not-Ready pod {pod_name} of {sts_name}")
        call("DELETE", f"/api/v1/namespaces/{ns}/pods/{pod_name}")
    if not stuck:
        print(f"dhcp-unstick: nothing to do ({len(stss)} DHCP StatefulSet(s), no stuck pod)")
    return stuck


def main():
    token = open(SA + "token").read().strip()
    ns = open(SA + "namespace").read().strip()
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    if ":" in host:
        host = "[" + host + "]"
    api = "https://" + host + ":" + os.environ["KUBERNETES_SERVICE_PORT"]
    ctx = ssl.create_default_context(cafile=SA + "ca.crt")

    def call(method, path, query=None):
        url = api + path + ("?" + urllib.parse.urlencode(query) if query else "")
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", "Bearer " + token)
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            return json.loads(resp.read())

    run(
        call,
        ns,
        os.environ["SELECTOR"],
        int(os.environ.get("MIN_UNREADY_SECONDS", "120")),
        datetime.datetime.now(datetime.timezone.utc),
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # best effort: never block the upgrade
        print(f"dhcp-unstick: skipped, {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(0)
