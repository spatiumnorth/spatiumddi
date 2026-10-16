"""BIND's DNSSEC keys outlive the dns-bind9 pod on the appliance (#1855).

The bind9 driver renders named's working ``directory`` as /var/cache/bind and
its ``key-directory`` inside it. ``dnssec-policy`` keeps every signed zone's
keys there, with the timing state that drives their rollovers. The appliance
chart persisted only the agent's state dir, so the keys lived in the
container: every new dns-bind9 pod (an upgrade, a reboot, an engine switch,
an eviction, a Fleet restart) signed every zone with new keys, and a DS
record published at the parent stopped matching. Validating resolvers then
answered SERVFAIL for the whole zone.

Three places have to agree, and each is pinned here:

  * the bind9 driver's ``key-directory``, read from the driver itself;
  * the appliance chart mounts a per-node hostPath on the persistent /var,
    under /var/lib/spatiumddi/agents/dns-bind9/, over that directory;
  * the image's entrypoint, which runs as root, creates the key directory and
    hands it to ``spatium`` before it drops to that user. kubelet creates a
    missing hostPath dir root:root 0755, and named, running as ``spatium``,
    could not write a key into it.

Lives in ``appliance/tests`` because that is the hermetic PyYAML job that
runs on every PR (see ``test_chart_pod_posture.py``); the chart templates
are Go templates, not YAML, so they are read as text.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_bind9_keys_persisted.py -v
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DRIVER = REPO / "agent" / "dns" / "spatium_dns_agent" / "drivers" / "bind9.py"
TEMPLATE = REPO / "charts" / "spatiumddi-appliance" / "templates" / "dns-bind9.yaml"
ENTRYPOINT = REPO / "agent" / "dns" / "images" / "bind9" / "entrypoint.sh"
HOST_ROOT = "/var/lib/spatiumddi/agents/dns-bind9/"


def _key_directory() -> str:
    """The one ``key-directory`` path the bind9 driver renders into named.conf."""
    found = set(re.findall(r'^\s*key-directory\s+"([^"]+)";', DRIVER.read_text(), re.MULTILINE))
    assert len(found) == 1, f"the bind9 driver renders key-directory as {sorted(found)}"
    return found.pop()


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _mounts(text: str) -> dict[str, str]:
    """mountPath -> volume name, for each ``- name: … / mountPath: …`` entry."""
    pairs = re.findall(r"^\s*- name: ([\w-]+)\s*\n\s*mountPath: (\S+)\s*$", text, re.MULTILINE)
    return {path: name for name, path in pairs}


def _host_paths(text: str) -> dict[str, tuple[str, str]]:
    """volume name -> (path, type), for each hostPath volume."""
    found = re.findall(
        r"^\s*- name: ([\w-]+)\s*\n\s*hostPath:\s*\n\s*path: (\S+)\s*\n\s*type: (\S+)\s*$",
        text,
        re.MULTILINE,
    )
    return {name: (path, kind) for name, path, kind in found}


def _commands(script: str) -> list[list[str]]:
    """The script's simple commands as argv lists, in order."""
    out: list[list[str]] = []
    for line in script.replace("\\\n", " ").splitlines():
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            continue
        argv: list[str] = []
        for word in words + [";"]:
            if word in ("&&", "||", ";", "|"):
                if argv:
                    out.append(argv)
                argv = []
            else:
                argv.append(word)
    return out


def test_the_chart_keeps_the_key_directory_on_a_per_node_host_path() -> None:
    keys = _key_directory()
    text = TEMPLATE.read_text()
    covering = [path for path in _mounts(text) if _inside(keys, path)]
    assert covering, (
        f"dns-bind9.yaml mounts no volume over named's key-directory {keys}: the "
        "DNSSEC keys live in the container and every new pod re-keys every signed zone"
    )
    mount = max(covering, key=len)
    volume = _mounts(text)[mount]
    host = _host_paths(text).get(volume)
    assert host, f"{volume!r}, mounted at {mount}, is not a hostPath volume"
    path, kind = host
    assert path.startswith(HOST_ROOT), (
        f"{volume!r} is the host dir {path}, not one under {HOST_ROOT} on the "
        "appliance's persistent /var"
    )
    assert kind == "DirectoryOrCreate", (
        f"{volume!r} has hostPath type {kind}: nothing else creates {path} on a new node"
    )


def test_the_entrypoint_hands_the_key_directory_to_named_s_user() -> None:
    keys = _key_directory()
    commands = _commands(ENTRYPOINT.read_text())

    def first(match) -> int:
        hits = [i for i, argv in enumerate(commands) if match(argv)]
        return hits[0] if hits else -1

    made = first(lambda a: a[0] == "mkdir" and "-p" in a and keys in a)
    owned = first(
        lambda a: a[0] == "chown"
        and "-R" in a
        and any(w.split(":")[0] == "spatium" for w in a[1:])
        and any(w.startswith("/") and _inside(keys, w) for w in a[1:])
    )
    dropped = first(
        lambda a: a[:2] == ["exec", "su-exec"] and len(a) > 2 and a[2].split(":")[0] == "spatium"
    )
    assert made >= 0, f"the entrypoint no longer runs `mkdir -p` on {keys}"
    assert owned >= 0, f"the entrypoint no longer runs `chown -R spatium` over {keys}"
    assert dropped >= 0, "the entrypoint no longer drops to spatium with `exec su-exec`"
    assert made < owned < dropped, (
        f"the entrypoint must create {keys}, then chown it to spatium, then drop to "
        "spatium, in that order: a key directory created after the chown, or owned "
        "by root, is one named cannot write to"
    )
