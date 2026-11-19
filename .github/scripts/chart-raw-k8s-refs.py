#!/usr/bin/env python3
"""Raw k8s/ manifests must point at Services that exist (#1547).

Nothing rendered or validated the raw manifests, so they drifted into
pointing at Services no manifest (or operator) ever creates:

* ``DATABASE_URL`` used host ``postgres-primary``. The CNPG Cluster in
  ``k8s/ha/postgres-cluster.yaml`` is named ``postgres``, so CNPG
  creates ``postgres-rw`` / ``postgres-ro`` / ``postgres-r`` — never
  ``postgres-primary``.
* The DNS/DHCP agents used ``CONTROL_PLANE_URL`` /
  ``SPATIUM_API_URL`` host ``spatiumddi-api``; the API Service is
  named ``api``.
* The Redis URLs were plain ``redis://redis-headless:6379/N``: the
  headless Service resolves to all three pods (a replica ~2 times in
  3, answering READONLY), the URLs carried no password while the
  manifest sets ``requirepass`` (NOAUTH), and no Service exposed the
  Sentinel port. They are now ``sentinel://`` URLs — per-pod headless
  names for ``REDIS_URL``, the ``redis-sentinel`` Service for Celery —
  with the password interpolated from the ``spatiumddi-secrets``
  Secret (``$(REDIS_PASSWORD)`` in the Deployments' env values: a
  ConfigMap never carries a credential, and interpolation does not
  expand in ConfigMap data).

This checks every ``k8s/**/*.yaml`` manifest: every URL host in an
env value or ConfigMap entry must resolve to a Service defined in
``k8s/`` or a CNPG-generated Service (``<cluster>-rw`` / ``-ro`` /
``-r``); every ``DATABASE_URL`` must use the ``-rw`` Service; the
api / worker / beat env Redis URLs must be ``sentinel://`` with a
password and must not live in the ConfigMap; and the
``redis-sentinel`` Service must exist on port 26379.

``k8s/ha/postgres-docker-compose.yaml`` is excluded: it is a Compose
file (its hosts are Compose service names, not Kubernetes Services)
and is documented as not working (#1236).

Usage: chart-raw-k8s-refs.py <k8s-dir>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml

URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'\)\]]+")
EXCLUDED_FILES = {"postgres-docker-compose.yaml"}
REDIS_URL_KEYS = ("REDIS_URL", "CELERY_BROKER_URL", "CELERY_RESULT_BACKEND")


def _strings(node) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for value in node.values() for s in _strings(value)]
    if isinstance(node, list):
        return [s for item in node for s in _strings(item)]
    return []


def _url_hosts(value: str) -> list[str]:
    hosts = []
    # Expand $(VAR) references first: the URL pattern below stops at a
    # closing paren, which would truncate the URL mid-userinfo and
    # report the username as the host.
    value = re.sub(r"\$\([^)]*\)", "VAR", value)
    for match in URL_RE.findall(value):
        netloc = urlparse(match).netloc or match.split("://", 1)[1].split("/", 1)[0]
        for part in netloc.split(","):
            host = part.rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
            if host:
                hosts.append(host)
    return hosts


def _env_entries(node) -> list[tuple[str, str]]:
    # Container env entries are the only dicts in these manifests
    # carrying both a string `name` and a string `value`.
    if isinstance(node, dict):
        entries = []
        name, value = node.get("name"), node.get("value")
        if isinstance(name, str) and isinstance(value, str):
            entries.append((name, value))
        for child in node.values():
            entries.extend(_env_entries(child))
        return entries
    if isinstance(node, list):
        return [entry for item in node for entry in _env_entries(item)]
    return []


def _is_cnpg_cluster(doc: dict) -> bool:
    # ``apiVersion`` is "<group>/<version>". Parse it rather than
    # substring-matching the group: read it as an authority + path and
    # compare the parsed host exactly, so a look-alike group such as
    # "postgresql.cnpg.io.evil.example/v1" never matches, while the
    # real "postgresql.cnpg.io/v1" (and a bare "postgresql.cnpg.io",
    # which has no version segment) behave exactly as before.
    parsed = urlparse(f"//{doc.get('apiVersion', '')}")
    return parsed.hostname == "postgresql.cnpg.io" and parsed.path.startswith("/")


def _resolves(host: str, services: set[str]) -> bool:
    # Short name, full FQDN (api.spatiumddi.svc.cluster.local), or a
    # per-pod headless name (redis-0.redis-headless.…): in each shape
    # one dotted component is the governing Service's name.
    return any(part in services for part in host.split("."))


def check(root: Path) -> list[str]:
    problems = []
    services: set[str] = set()
    cnpg_clusters: list[str] = []
    docs_by_file: dict[Path, list[dict]] = {}

    files = sorted(
        p
        for p in root.rglob("*.yaml")
        if p.name not in EXCLUDED_FILES and not p.name.endswith(".example")
    )
    for path in files:
        docs = [d for d in yaml.safe_load_all(path.read_text()) if isinstance(d, dict)]
        docs_by_file[path] = docs
        for doc in docs:
            meta = doc.get("metadata") or {}
            if doc.get("kind") == "Service" and meta.get("name"):
                services.add(meta["name"])
            if doc.get("kind") == "Cluster" and _is_cnpg_cluster(doc):
                cnpg_clusters.append(meta.get("name", ""))
    for cluster in cnpg_clusters:
        services.update({f"{cluster}-rw", f"{cluster}-ro", f"{cluster}-r"})

    sentinel_service_ok = False
    redis_env_seen: set[str] = set()
    for path, docs in docs_by_file.items():
        for doc in docs:
            meta = doc.get("metadata") or {}
            if doc.get("kind") == "Service" and meta.get("name") == "redis-sentinel":
                ports = (doc.get("spec") or {}).get("ports") or []
                sentinel_service_ok = any(p.get("port") == 26379 for p in ports)
            for value in _strings(doc):
                for host in _url_hosts(value):
                    if host in ("0.0.0.0",) or "$" in host:
                        continue
                    if not _resolves(host, services):
                        problems.append(
                            f"{path}: URL host {host!r} does not resolve to "
                            "any Service defined in k8s/ or created by the "
                            "CNPG Cluster (#1547)"
                        )
                if "DATABASE_URL" in value or value.startswith("postgresql"):
                    for host in _url_hosts(value):
                        if cnpg_clusters and host not in {f"{c}-rw" for c in cnpg_clusters}:
                            problems.append(
                                f"{path}: DATABASE_URL host {host!r} is not "
                                "the CNPG read/write Service "
                                f"({', '.join(c + '-rw' for c in cnpg_clusters)}) "
                                "(#1547)"
                            )
            # The Redis URLs live in the Deployments' env values, not
            # the ConfigMap: they embed the password (interpolated
            # from the Secret as $(REDIS_PASSWORD)), and interpolation
            # only expands in an env `value`.
            for env_name, env_value in _env_entries(doc):
                if env_name not in REDIS_URL_KEYS:
                    continue
                redis_env_seen.add(env_name)
                if not env_value.startswith("sentinel://"):
                    problems.append(
                        f"{path}: {env_name} is {env_value!r}, not a "
                        "sentinel:// URL — a plain client against the "
                        "headless Service lands on a replica and gets "
                        "READONLY (#1547)"
                    )
                elif "@" not in env_value.split("://", 1)[1].split("/", 1)[0]:
                    problems.append(
                        f"{path}: {env_name} carries no password, but the "
                        "Redis manifest sets requirepass — connections "
                        "fail with NOAUTH (#1547)"
                    )
            if doc.get("kind") == "ConfigMap" and meta.get("name") == "spatiumddi-config":
                data = doc.get("data") or {}
                for key in REDIS_URL_KEYS + ("REDIS_SENTINEL_PASSWORD",):
                    if key in data:
                        problems.append(
                            f"{path}: {key} is set in the ConfigMap — the "
                            "Redis password belongs in the "
                            "spatiumddi-secrets Secret, interpolated as "
                            "$(REDIS_PASSWORD) in the Deployments' env, "
                            "never in a ConfigMap (#1547)"
                        )
    for key in REDIS_URL_KEYS:
        if key not in redis_env_seen:
            problems.append(
                f"{key} is not set in any env in k8s/ — the api / "
                "worker / beat must carry the sentinel:// URL inline "
                "with $(REDIS_PASSWORD) interpolated (#1547)"
            )
    if not sentinel_service_ok:
        problems.append(
            "no Service named redis-sentinel exposing port 26379 is "
            "defined in k8s/ — the Celery sentinel:// URLs have nothing "
            "to connect to (#1547)"
        )
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    problems = check(Path(argv[0]))
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        print("   raw k8s/ manifests point at Services that exist")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
