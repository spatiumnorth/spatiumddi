"""One zone whose files cannot be named must not stop the server (#3672).

A zone name may be 253 characters, and the agent stores a zone as
``<zone>.db`` with sidecars beside it (``.db.sha256``, #2157; ``.db.owned``,
#2850) and temp names past those. A file name is capped at 255 bytes, so a
long zone has names the file system refuses with ``ENAMETOOLONG``. The #1403
hold-back of a refused zone deleted its sidecar with ``unlink(missing_ok=True)``,
which tolerates a missing file but not a name too long: the error left the
driver and the agent rejected its whole configuration, the #1403 failure
again. Live, a 250-character zone with no Primary NS stopped every change to
its group until it was deleted.

These use real long names on the test's file system rather than a mocked
``unlink``, except where an error the file system will not produce on demand
is the point.
"""

from __future__ import annotations

import errno
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver


def _long(n: int, tail: str = "example.test") -> str:
    """A valid DNS name of exactly ``n`` characters (labels <= 63)."""
    labels: list[str] = []
    room = n - len(tail)
    while room > 0:
        size = min(60, room - 1)
        labels.append("a" * size)
        room -= size + 1
    name = ".".join([*labels, tail])
    assert len(name) == n, len(name)
    return name


SOA = (
    "$TTL 300\n@ IN SOA ns1.example.test. host.example.test. "
    "( {serial} 3600 600 86400 300 )\n@ IN NS ns1.example.test.\n"
)


def _zone(root: Path, zname: str, serial: int) -> Path:
    path = root / "zones" / f"{zname}.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SOA.format(serial=serial))
    return path


def _stage(tmp_path: Path) -> Path:
    new = tmp_path / "rendered.new"
    new.mkdir(parents=True)
    (new / "named.conf").write_text("options {};\n")
    return new


def _tools(monkeypatch: pytest.MonkeyPatch, refused: set[str]) -> None:
    """named-checkconf passes; named-checkzone refuses the zones in ``refused``."""
    monkeypatch.setattr(bind9.shutil, "which", lambda name: f"/usr/sbin/{name}")

    def run(cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        if Path(cmd[0]).name == "named-checkzone" and cmd[-2] in refused:
            return subprocess.CompletedProcess(
                cmd, 1, f"zone {cmd[-2]}/IN: not loaded due to errors.\n", ""
            )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)


@pytest.fixture(autouse=True)
def _name_max_is_255(tmp_path: Path) -> None:
    if os.pathconf(tmp_path, "PC_NAME_MAX") != 255:
        pytest.skip("these names are sized for a 255-byte NAME_MAX")


# ── the hold-back of a refused zone (#1403 + #2157) ──────────────────────────


def test_a_refused_new_zone_whose_sidecar_cannot_be_named_is_held_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The case met live: 250 characters, so ``.db`` (253) exists and
    ``.db.sha256`` (260) cannot. The zone is held back, the other applies."""
    long = _long(250)
    new = _stage(tmp_path)
    _zone(new, long, 1)
    good = _zone(new, "good.test", 1).read_bytes()
    _tools(monkeypatch, {long})

    drv = Bind9Driver(tmp_path)
    drv.validate()  # used to raise [Errno 36] File name too long

    assert not (new / "zones" / f"{long}.db").exists()
    assert (new / "zones" / "good.test.db").read_bytes() == good
    assert [(h.zone, h.served) for h in drv.held_back] == [(long, False)]


def test_a_sidecar_delete_that_raises_name_too_long_is_nothing_to_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same, for a short name with the error simulated: the hold-back
    must not depend on which of the zone's files the limit falls on."""
    new = _stage(tmp_path)
    _zone(new, "bad.test", 1)
    _zone(new, "good.test", 1)
    _tools(monkeypatch, {"bad.test"})
    real_unlink = Path.unlink

    def unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name.endswith((".sha256", ".owned")):
            raise OSError(errno.ENAMETOOLONG, "File name too long", str(self))
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)

    drv = Bind9Driver(tmp_path)
    drv.validate()

    assert not (new / "zones" / "bad.test.db").exists()
    assert (new / "zones" / "good.test.db").exists()
    assert [(h.zone, h.served) for h in drv.held_back] == [("bad.test", False)]


def test_any_other_error_holding_a_zone_back_is_logged_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    new = _stage(tmp_path)
    _zone(new, "bad.test", 1)
    _zone(new, "good.test", 1)
    _tools(monkeypatch, {"bad.test"})
    real_unlink = Path.unlink

    def unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name == "bad.test.db":
            raise PermissionError(errno.EACCES, "Permission denied", str(self))
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)

    drv = Bind9Driver(tmp_path)
    drv.validate()

    assert [(h.zone, h.served) for h in drv.held_back] == [("bad.test", False)]
    assert (new / "zones" / "good.test.db").exists()


def test_a_refused_edit_of_a_long_zone_keeps_its_live_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """250 characters: the live copy goes back over the staged file even
    though the copy's temp name (``.db.tmp``, 257) cannot exist."""
    long = _long(250)
    new = _stage(tmp_path)
    kept = _zone(tmp_path / "rendered", long, 1).read_bytes()
    _zone(new, long, 2)
    _tools(monkeypatch, {long})

    drv = Bind9Driver(tmp_path)
    drv.validate()

    assert (new / "zones" / f"{long}.db").read_bytes() == kept
    assert [(h.zone, h.served) for h in drv.held_back] == [(long, True)]


# ── the render: a zone whose own file cannot be named ────────────────────────


def _primary(name: str, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 2026110601,
        "primary_ns": "ns1.example.test.",
        "admin_email": "hostmaster.example.test.",
        "records": [{"name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300}],
        **extra,
    }


def _bundle(
    zones: list[dict[str, Any]], blocklists: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "zones": zones,
        "tsig_keys": [],
        "blocklists": blocklists or [],
    }


def test_a_zone_whose_file_cannot_be_named_is_held_back_at_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """253 characters: ``.db`` is 256. The render used to raise out of the
    driver; now the zone is held back and every other zone renders."""
    long = _long(253)
    drv = Bind9Driver(tmp_path)
    drv.render(_bundle([_primary(long + "."), _primary("good.test.")]))
    new = tmp_path / "rendered.new"

    assert (new / "zones" / "good.test.db").is_file()
    assert not any(p.name.startswith("aaa") for p in (new / "zones").iterdir())
    # The stanza stays: named answers SERVFAIL for the zone rather than
    # handing its names to recursion.
    assert f'zone "{long}."' in (new / "named.conf").read_text()

    _tools(monkeypatch, set())
    drv.validate()
    assert [(h.zone, h.view, h.served) for h in drv.held_back] == [(long, None, False)]
    assert "too long for the agent to store the zone" in drv.held_back[0].reason
    assert "Shorten the zone name" in drv.held_back[0].reason


def test_a_dynamic_zone_whose_ownership_sidecar_cannot_be_named_is_held_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """250 characters: ``.db`` fits and ``.db.owned`` does not. A zone file
    with no ownership record would be misread by the next render (#2850), so
    the file is not left behind on its own."""
    long = _long(250)
    drv = Bind9Driver(tmp_path)
    drv.render(_bundle([_primary(long + ".", dynamic_update_enabled=True)]))

    assert not (tmp_path / "rendered.new" / "zones" / f"{long}.db").exists()
    assert [(h.zone, h.served) for h in drv._unwritable_zones] == [(long, False)]


def test_an_rpz_zone_with_no_room_for_its_hash_sidecar_is_still_served(
    tmp_path: Path,
) -> None:
    """The sidecar is an optimisation (#2157): without room for it the zone
    is rendered every time, and served."""
    rpz = _long(246, tail="rpz")
    bl = {
        "rpz_zone_name": rpz + ".",
        "entries": [
            {
                "domain": "ads.example.test",
                "action": "block",
                "block_mode": "nxdomain",
                "target": None,
                "is_wildcard": False,
            }
        ],
        "exceptions": [],
        "view_name": None,
        "rpz_sha256": "sha256:" + "a" * 64,
    }
    drv = Bind9Driver(tmp_path)
    drv.render(_bundle([_primary("good.test.")], [bl]))

    assert (tmp_path / "rendered.new" / "zones" / f"{rpz}.db").is_file()
    assert drv._unwritable_zones == ()


# ── named's own files: the journal it opens on every load ────────────────────
#
# named opens ``<file>.jnl`` when it loads a primary zone, dynamic or not, and
# with inline-signing ``<file>.signed.jnl``; a name past NAME_MAX is "journal
# open failed ... not loaded due to errors" (BIND 9.20, live_long_zone_check).
# Written anyway, such a zone passed named-checkzone and failed the reload
# verification, and with it the whole apply.


@pytest.mark.parametrize(
    ("length", "signed", "held"),
    [
        pytest.param(248, False, False, id="248-journal-fits"),
        pytest.param(249, False, True, id="249-journal-too-long"),
        pytest.param(241, True, False, id="241-signed-journal-fits"),
        pytest.param(242, True, True, id="242-signed-journal-too-long"),
    ],
)
def test_a_zone_whose_journal_named_cannot_name_is_held_back_at_render(
    tmp_path: Path, length: int, signed: bool, held: bool
) -> None:
    long = _long(length)
    extra: dict[str, Any] = (
        {"dnssec_enabled": True, "dnssec_policy_name": "default"} if signed else {}
    )
    drv = Bind9Driver(tmp_path)
    drv.render(_bundle([_primary(long + ".", **extra), _primary("good.test.")]))
    new = tmp_path / "rendered.new"

    assert (new / "zones" / "good.test.db").is_file()
    assert (new / "zones" / f"{long}.db").is_file() is not held
    assert f'zone "{long}."' in (new / "named.conf").read_text()
    if held:
        assert [(h.zone, h.served) for h in drv._unwritable_zones] == [(long, False)]
        assert "Shorten the zone name" in drv._unwritable_zones[0].reason
    else:
        assert drv._unwritable_zones == ()


def test_an_rpz_zone_whose_journal_named_cannot_name_is_held_back(
    tmp_path: Path,
) -> None:
    rpz = _long(249, tail="rpz")
    bl = {
        "rpz_zone_name": rpz + ".",
        "entries": [],
        "exceptions": [],
        "view_name": None,
    }
    drv = Bind9Driver(tmp_path)
    drv.render(_bundle([_primary("good.test.")], [bl]))

    assert not (tmp_path / "rendered.new" / "zones" / f"{rpz}.db").exists()
    assert [(h.zone, h.served) for h in drv._unwritable_zones] == [(rpz, False)]


def test_the_hold_is_cleared_when_the_zone_is_gone(tmp_path: Path) -> None:
    """``_unwritable_zones`` is per render: a zone deleted or renamed short
    is not held by the next apply."""
    drv = Bind9Driver(tmp_path)
    drv.render(_bundle([_primary(_long(253) + "."), _primary("good.test.")]))
    assert drv._unwritable_zones != ()
    drv.render(_bundle([_primary("good.test.")]))
    assert drv._unwritable_zones == ()
