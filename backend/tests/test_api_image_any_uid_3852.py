"""The api image's writable paths are usable by any uid in group 0 (#3852).

OpenShift's restricted SCC runs the api and worker as a random uid whose only
group is 0, and the chart mounts nothing over ``/var/lib/spatiumddi`` there, so
local backups, pcaps and the cert store write into the image's own directories.
Owned ``app:app`` with no group-0 bits they answer EACCES. Docker's build is not
run here; this pins the one RUN that sets the modes, in the stage that ships.
"""

from __future__ import annotations

import pathlib
import re

_DOCKERFILE = pathlib.Path(__file__).resolve().parents[1] / "Dockerfile"


def _runtime_run_that_creates_the_state_dirs() -> str:
    text = _DOCKERFILE.read_text()
    # Join continuation lines and drop in-RUN comment lines, as BuildKit does.
    logical: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        buf += " " + line.rstrip("\\")
        if not raw.rstrip().endswith("\\"):
            logical.append(buf.strip())
            buf = ""
    runs = [ln for ln in logical if ln.startswith("RUN ") and "mkdir -p /var/lib/spatiumddi" in ln]
    assert len(runs) == 1, runs
    return runs[0]


def test_every_state_dir_is_group_0_and_carries_the_owner_bits() -> None:
    run = _runtime_run_that_creates_the_state_dirs()
    steps = [s.strip() for s in run.split("&&")]
    chown = steps.index("chown -R app:app /var/lib/spatiumddi")
    # After the chown (which would reset the group) and covering the whole tree.
    assert "chgrp -R 0 /var/lib/spatiumddi" in steps[chown + 1 :]
    assert "chmod -R g=u /var/lib/spatiumddi" in steps[chown + 1 :]
    # Never world-writable: g=u copies the owner bits, it adds nothing for others.
    assert not re.search(r"chmod[^&]*o\+w|chmod[^&]*\b07\d7\b", run)
