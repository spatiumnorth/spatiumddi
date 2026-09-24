"""The local-volume backup path is ONE store for the api and the worker (#1160).

A ``local_volume`` backup target at its default path,
``/var/lib/spatiumddi/backups``, is written from two places: the api (a
manual "Run now", restore's pre-restore safety dump) and the worker (every
scheduled run). The api lists, downloads and restores from it. So both
must see the same storage there, or each writes into its own container
layer: scheduled archives are never listed, and every archive is lost when
the container or pod is replaced. The release Docker Compose file shipped
that volume commented out on both services, and the chart mounted nothing
there — with every run reporting success.

Three places have to agree, and each is pinned here:

  * ``docker-compose.yml`` mounts one named volume at the path on api AND
    worker, and declares it;
  * the umbrella chart mounts the ``backups`` hostPath at the path in the
    api AND worker templates when the appliance host mounts are on;
  * ``spatiumddi-firstboot`` creates that host dir owned by uid 1000 (the
    pods' uid) — kubelet's DirectoryOrCreate would make it root:root 0755
    and every backup write would fail EACCES.

Lives in ``appliance/tests`` because that is the hermetic PyYAML job that
runs on every PR (see ``test_chart_pod_posture.py``); the chart templates
are Go templates, not YAML, so they are read as text.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_backup_volume_shared.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent.parent
BACKUP_PATH = "/var/lib/spatiumddi/backups"


def _volume_at(service: dict, path: str) -> str | None:
    """The named volume a compose service mounts at ``path``, if any."""
    for entry in service.get("volumes") or []:
        if isinstance(entry, str):
            source, _, target = entry.partition(":")
            target = target.split(":", 1)[0]
        else:
            source, target = entry.get("source"), entry.get("target")
        if target == path:
            return source
    return None


def test_compose_mounts_one_backup_volume_on_api_and_worker() -> None:
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    services = compose["services"]
    api = _volume_at(services["api"], BACKUP_PATH)
    worker = _volume_at(services["worker"], BACKUP_PATH)
    assert api, f"the api mounts nothing at {BACKUP_PATH}"
    assert worker, f"the worker mounts nothing at {BACKUP_PATH}"
    assert api == worker, (
        f"api mounts {api!r} and worker mounts {worker!r} at {BACKUP_PATH}: two "
        "stores, so the api never lists what the worker's scheduled runs write"
    )
    assert api in (compose.get("volumes") or {}), (
        f"{api!r} is mounted but not declared under the top-level volumes:"
    )


def _template(name: str) -> str:
    return (REPO / "charts" / "spatiumddi" / "templates" / name).read_text()


def test_chart_mounts_the_backups_host_path_on_api_and_worker() -> None:
    mount = re.compile(
        r"- name: backups\s*\n\s*mountPath: " + re.escape(BACKUP_PATH) + r"\s*\n"
    )
    volume = re.compile(
        r"- name: backups\s*\n\s*hostPath:\s*\n\s*path: "
        r"\{\{ \.Values\.api\.applianceHostMounts\.backupsDir \}\}"
    )
    for name in ("api.yaml", "worker.yaml"):
        text = _template(name)
        assert mount.search(text), f"{name} does not mount 'backups' at {BACKUP_PATH}"
        assert volume.search(text), (
            f"{name}'s 'backups' volume is not the applianceHostMounts.backupsDir hostPath"
        )
    values = yaml.safe_load((REPO / "charts" / "spatiumddi" / "values.yaml").read_text())
    assert values["api"]["applianceHostMounts"]["backupsDir"] == BACKUP_PATH


def test_firstboot_hands_the_backups_host_dir_to_the_pods_uid() -> None:
    firstboot = (
        REPO / "appliance" / "mkosi.extra" / "usr" / "local" / "bin" / "spatiumddi-firstboot"
    ).read_text()
    for line in (
        f"mkdir -p {BACKUP_PATH}",
        f"chown 1000:1000 {BACKUP_PATH}",
        f"chmod 0700 {BACKUP_PATH}",
    ):
        assert re.search(rf"^{re.escape(line)}$", firstboot, re.MULTILINE), (
            f"spatiumddi-firstboot no longer runs `{line}`"
        )
