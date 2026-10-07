"""The k3s join token is published whenever k3s writes it (#1509).

`spatiumddi-publish-k3s-token.service` runs once at boot and polls for the
token for 60 s. On a fresh seed the token could land after that window, and
nothing ran the service again until a reboot, so promoting the second node
answered 409 ("the control-plane seed hasn't reported its k3s join token").
A `.path` unit now re-runs it when the token file is written.

    python3 -m pytest appliance/tests/test_publish_k3s_token_path.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
UNITS = REPO / "appliance" / "mkosi.extra" / "etc" / "systemd" / "system"
SCRIPT = REPO / "appliance" / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-publish-k3s-token"
PATH_UNIT = UNITS / "spatiumddi-publish-k3s-token.path"
SERVICE = UNITS / "spatiumddi-publish-k3s-token.service"

pytestmark = pytest.mark.skipif(not UNITS.is_dir(), reason="appliance tree not present")


def _token_file_the_script_reads() -> str:
    m = re.search(r"^TOKEN_FILE=(\S+)$", SCRIPT.read_text(encoding="utf-8"), re.M)
    assert m, "spatium-publish-k3s-token no longer sets TOKEN_FILE"
    return m.group(1)


def test_path_unit_watches_the_token_the_script_publishes() -> None:
    body = PATH_UNIT.read_text(encoding="utf-8")
    watched = re.findall(r"^PathChanged=(\S+)$", body, re.M)
    assert watched == [_token_file_the_script_reads()]
    assert re.search(r"^Unit=spatiumddi-publish-k3s-token\.service$", body, re.M)


def test_path_unit_is_edge_triggered() -> None:
    # PathExists= is level-triggered: it restarts the oneshot every time it
    # finishes while the file exists, until the start limit takes it down.
    body = PATH_UNIT.read_text(encoding="utf-8")
    assert not re.search(r"^PathExists(Glob)?=", body, re.M)


def test_boot_run_is_kept() -> None:
    # The .path unit only sees a token written after it starts; a token that
    # already exists at boot is still published by the service's own run.
    assert re.search(r"^\[Install\]", SERVICE.read_text(encoding="utf-8"), re.M)
