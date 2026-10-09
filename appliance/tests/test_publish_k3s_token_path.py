"""The k3s join token is published whenever k3s writes it (#1509).

``spatiumddi-publish-k3s-token.service`` ran once at boot and polled for the
token for 60 s. On a fresh seed k3s could write it later, nothing published it
until a reboot, and promoting the second node answered 409. A ``.path`` unit
now re-runs the service on every write of the token file.

    python3 -m pytest appliance/tests/test_publish_k3s_token_path.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
UNIT_DIR = REPO / "appliance" / "mkosi.extra" / "etc" / "systemd" / "system"
SCRIPT = REPO / "appliance" / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-publish-k3s-token"
POSTINST = REPO / "appliance" / "mkosi.postinst"
PATH_UNIT = UNIT_DIR / "spatiumddi-publish-k3s-token.path"
SERVICE = UNIT_DIR / "spatiumddi-publish-k3s-token.service"

pytestmark = pytest.mark.skipif(
    not UNIT_DIR.is_dir(), reason="appliance tree not present in this checkout"
)


def _directives(text: str, key: str) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(rf"^{key}=(.*)$", text, re.MULTILINE)]


def _script_token_file() -> str:
    m = re.search(r"^TOKEN_FILE=(\S+)$", SCRIPT.read_text(), re.MULTILINE)
    assert m, "spatium-publish-k3s-token no longer sets TOKEN_FILE"
    return m.group(1)


def test_path_unit_watches_the_token_the_script_reads() -> None:
    assert PATH_UNIT.is_file(), "spatiumddi-publish-k3s-token.path is missing"
    text = PATH_UNIT.read_text()
    assert _directives(text, "PathChanged") == [_script_token_file()]
    assert _directives(text, "Unit") == [SERVICE.name]


def test_path_unit_is_edge_triggered() -> None:
    # PathExists= re-fires the oneshot each time it exits while the token
    # exists, until the start limit takes the unit down.
    text = PATH_UNIT.read_text()
    for key in ("PathExists", "PathExistsGlob", "DirectoryNotEmpty"):
        assert not _directives(text, key), f"{key}= is level-triggered"


def test_boot_run_is_kept_and_path_unit_enabled() -> None:
    # A .path unit only sees writes after it starts; a token that already
    # exists at boot still needs the service's own boot run.
    assert re.search(r"^WantedBy=multi-user\.target$", SERVICE.read_text(), re.MULTILINE)
    postinst = POSTINST.read_text()
    assert re.search(r"^\s*spatiumddi-publish-k3s-token\.path \\$", postinst, re.MULTILINE)
