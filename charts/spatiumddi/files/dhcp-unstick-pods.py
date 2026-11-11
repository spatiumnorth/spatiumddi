"""Delete the DHCP agent StatefulSets of this release that hold a stuck pod (#3907).

Run by the ``pre-upgrade`` hook in templates/dhcp-agent-unstick.yaml, stdlib
only. A StatefulSet with ``OrderedReady`` + ``RollingUpdate`` will not replace a
pod that is not Ready, so a pod that was never Ready on the old release (the
old readiness probe could never pass) keeps the new image from ever rolling
out. Deleting just the pod does not help: this hook runs BEFORE Helm updates
the StatefulSet, so the controller would recreate the pod from the OLD
template, unready again. So the StatefulSet object itself is deleted (with its
stuck pods; the PVCs from volumeClaimTemplates are kept), and ``helm upgrade``
then creates it from the NEW template, because a release resource that is
missing from the cluster is created.

A StatefulSet is only touched if one of its pods is Running, not Ready, and has
been not Ready for at least MIN_UNREADY_SECONDS, and only if it carries the
release's DHCP agent labels. A StatefulSet whose pods are Ready is never
touched. Best effort: any error is logged and the hook still exits 0, so this
can never be the reason an upgrade fails.
"""

import datetime
import json
import os
import ssl
import sys
import time
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


def _wait_gone(call, path, sleep, tries=30):
    for _ in range(tries):
        try:
            call("GET", path)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return True
            raise
        sleep(2)
    return False


def run(call, ns, selector, min_unready, now, sleep=time.sleep):
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
    by_sts = {}
    for sts_name, pod_name in stuck:
        by_sts.setdefault(sts_name, []).append(pod_name)
    background = {"kind": "DeleteOptions", "apiVersion": "v1", "propagationPolicy": "Background"}
    for sts_name, pod_names in by_sts.items():
        sts_path = f"/apis/apps/v1/namespaces/{ns}/statefulsets/{sts_name}"
        print(f"dhcp-unstick: deleting StatefulSet {sts_name} (not-Ready pod {pod_names})")
        call("DELETE", sts_path, None, background)
        for pod_name in pod_names:
            try:
                call("DELETE", f"/api/v1/namespaces/{ns}/pods/{pod_name}")
            except urllib.error.HTTPError as exc:
                if exc.code != 404:  # already collected with its StatefulSet
                    raise
        if not _wait_gone(call, sts_path, sleep):
            print(f"dhcp-unstick: StatefulSet {sts_name} still present after 60s")
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

    def call(method, path, query=None, body=None):
        url = api + path + ("?" + urllib.parse.urlencode(query) if query else "")
        req = urllib.request.Request(
            url, method=method, data=json.dumps(body).encode() if body else None
        )
        req.add_header("Authorization", "Bearer " + token)
        if body:
            req.add_header("Content-Type", "application/json")
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
