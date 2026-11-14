"""#4192 -- named's freed memory goes back to the OS.

Alpine's named runs on musl malloc, which keeps freed pages, so a removed view
or a reload left every RPZ copy resident. The image links jemalloc into named
and tunes it through /etc/malloc.conf, which (unlike LD_PRELOAD / MALLOC_CONF)
a binary with a file capability still honours.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

IMAGE = Path(__file__).resolve().parents[1] / "images" / "bind9"
DOCKERFILE = (IMAGE / "Dockerfile").read_text()
ENTRYPOINT = (IMAGE / "entrypoint.sh").read_text()
SCRIPT = IMAGE / "malloc-conf.sh"


def _run_script(tmp_path: Path, env: dict[str, str]) -> tuple[subprocess.CompletedProcess, Path]:
    link = tmp_path / "malloc.conf"
    full = {"PATH": os.environ["PATH"], "MALLOC_CONF_LINK": str(link), **env}
    return (
        subprocess.run(["sh", str(SCRIPT)], env=full, capture_output=True, text=True),
        link,
    )


def test_image_defaults_decay_and_background_thread() -> None:
    m = re.search(r'ln -sfn "([^"]+)" /etc/malloc\.conf', DOCKERFILE)
    assert m, "Dockerfile must bake the /etc/malloc.conf symlink"
    opts = dict(o.split(":") for o in m.group(1).split(","))
    assert opts["background_thread"] == "true"
    assert int(opts["dirty_decay_ms"]) <= 10_000
    assert int(opts["muzzy_decay_ms"]) <= 10_000


def test_named_is_linked_to_jemalloc_before_setcap() -> None:
    assert "jemalloc" in DOCKERFILE
    patch = DOCKERFILE.index("patchelf --add-needed libjemalloc.so.2 /usr/sbin/named")
    setcap = DOCKERFILE.index("setcap cap_net_bind_service=+ep /usr/sbin/named")
    assert patch < setcap, "patchelf rewrites the file and drops the capability"
    assert "ldd /usr/sbin/named | grep -q libjemalloc" in DOCKERFILE


def test_entrypoint_runs_override_before_agent() -> None:
    assert ENTRYPOINT.index("spatium-malloc-conf") < ENTRYPOINT.index("exec su-exec")


def test_override_replaces_the_options(tmp_path: Path) -> None:
    r, link = _run_script(tmp_path, {"SPATIUM_MALLOC_CONF": "dirty_decay_ms:500"})
    assert r.returncode == 0
    assert os.readlink(link) == "dirty_decay_ms:500"


def test_unset_keeps_the_shipped_options(tmp_path: Path) -> None:
    link = tmp_path / "malloc.conf"
    link.symlink_to("shipped")
    r, _ = _run_script(tmp_path, {})
    assert r.returncode == 0
    assert os.readlink(link) == "shipped"


def test_unwritable_link_does_not_fail_startup(tmp_path: Path) -> None:
    r, _ = _run_script(
        tmp_path, {"SPATIUM_MALLOC_CONF": "x:1", "MALLOC_CONF_LINK": "/proc/nope/malloc.conf"}
    )
    assert r.returncode == 0
    assert "ignored" in r.stderr
