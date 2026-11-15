"""A small blocklist change is sent to named as RFC 2136 updates (#4191).

A refresh used to re-render the whole RPZ zone and reload it, so named held
the old and the new copy of a zone of hundreds of thousands of names at once.
Now a zone named takes updates for (the agent's own key is in its
``allow-update``) is diffed against a snapshot of what named already holds,
and a small diff goes over loopback instead: no freeze, no reload, no second
copy. Anything else is the reload it always was.

These run a model of named behind ``dns.query.tcp``: it applies the update
messages the agent sends to an in-memory zone and answers the read-back
queries from it. So what is asserted is the zone named would end up with
(equal to the new render, line for line), the keys the messages were signed
with, and which ``rndc`` verbs were issued, not the agent's own helper calls.
"""

from __future__ import annotations

import subprocess
import zlib
from pathlib import Path
from typing import Any

import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.update
import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver

RPZ = "spatium-blocklist.rpz."
RPZ_FILE = "zones/spatium-blocklist.rpz.db"
SECRET = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"
LOOPBACK = {"name": "spatium-loopback", "secret": SECRET, "algorithm": "hmac-sha256"}


def _bl(
    names: list[str],
    *,
    zone: str = RPZ,
    view: str | None = None,
    exceptions: tuple[str, ...] = ("allowed.example.test",),
    digest: str | None = None,
) -> dict[str, Any]:
    # An entry's mode follows its name, not its position: moving a name in the
    # list must not change what it renders as.
    entries = [
        {
            "domain": n,
            "action": "block",
            "block_mode": "sinkhole" if zlib.crc32(n.encode()) % 7 == 0 else "nxdomain",
            "target": None,
            "is_wildcard": zlib.crc32(n.encode()) % 3 == 0,
        }
        for n in names
    ]
    return {
        "rpz_zone_name": zone,
        "entries": entries,
        "exceptions": list(exceptions),
        "view_name": view,
        "rpz_sha256": digest or "sha256:" + format(zlib.crc32(" ".join(names).encode()), "x").ljust(64, "0"),
    }


def _names(prefix: str, n: int = 300) -> list[str]:
    return [f"{prefix}{i:04d}.example.test" for i in range(n)]


def _flat(blocklists: list[dict[str, Any]], *, keys: bool = True) -> dict[str, Any]:
    return {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "zones": [],
        "tsig_keys": [dict(LOOPBACK, loopback=True)] if keys else [],
        "blocklists": blocklists,
    }


def _views(blocklists: list[dict[str, Any]]) -> dict[str, Any]:
    def view(name: str, order: int) -> dict[str, Any]:
        return {
            "id": name,
            "name": name,
            "match_clients": ["10.0.0.0/8"] if order == 0 else ["any"],
            "match_destinations": [],
            "recursion": True,
            "order": order,
            "transfer_key": {
                "name": f"spatium-view-{name}",
                "secret": SECRET,
                "algorithm": "hmac-sha256",
            },
        }

    return {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "views": [view("internal", 0), view("external", 1)],
        "zones": [],
        "tsig_keys": [dict(LOOPBACK, loopback=True)],
        "blocklists": blocklists,
    }


class _Named:
    """A named, as far as the agent can tell: ``rndc`` verbs and RFC 2136."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.rndc: list[list[str]] = []
        self.messages: list[Any] = []
        # (zone, key name) -> {(owner, type, rdata)}; keyed by the key because
        # that is what picks the view.
        self.zones: dict[str, set[tuple[str, str, str]]] = {}
        self.rcode = dns.rcode.NOERROR
        self.ignore_adds = False

    # -- rndc
    def run(self, cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess[str]:
        self.rndc.append(list(cmd))
        out = ""
        if "zonestatus" in cmd:
            i = cmd.index("zonestatus")
            view = cmd[i + 3] if len(cmd) > i + 3 else None
            live = self.root / "rendered" / bind9._zone_rel(cmd[i + 1], view)
            serial = bind9._soa_serial(live)
            out = f"serial: {serial}\n" if serial is not None else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")

    def verbs(self, verb: str) -> list[str]:
        return [c[c.index(verb) + 1] for c in self.rndc if verb in c]

    # -- RFC 2136
    def tcp(self, msg: Any, where: str, **kw: Any) -> Any:
        if isinstance(msg, dns.update.UpdateMessage):
            return self._update(msg)
        return self._query(msg)

    def _view(self, msg: Any) -> str:
        return msg.keyname.to_text(omit_final_dot=True) if msg.keyname else ""

    def _update(self, msg: Any) -> Any:
        self.messages.append(msg)
        resp = dns.message.make_response(msg)
        if self.rcode != dns.rcode.NOERROR:
            resp.set_rcode(self.rcode)
            return resp
        zone = self.zones.setdefault(self._view(msg), set())
        for rrset in msg.update:
            owner = rrset.name.derelativize(msg.origin).to_text()
            rtype = dns.rdatatype.to_text(rrset.rdtype)
            if rrset.deleting == dns.rdataclass.NONE:
                for rd in rrset:
                    zone.discard((owner, rtype, rd.to_text()))
            elif rrset.deleting == dns.rdataclass.ANY:
                for t in {t for t in zone if t[0] == owner and t[1] == rtype}:
                    zone.discard(t)
            elif not self.ignore_adds:
                for rd in rrset:
                    zone.add((owner, rtype, rd.to_text()))
        return resp

    def _query(self, msg: Any) -> Any:
        resp = dns.message.make_response(msg)
        q = msg.question[0]
        zone = self.zones.get(self._view(msg), set())
        owner = q.name.to_text()
        rtype = dns.rdatatype.to_text(q.rdtype)
        for o, t, rd in sorted(zone):
            if o == owner and t == rtype:
                rrset = resp.find_rrset(
                    resp.answer, q.name, dns.rdataclass.IN, q.rdtype, create=True
                )
                rrset.add(dns.rdata.from_text(dns.rdataclass.IN, q.rdtype, rd), 60)
        return resp

    def load(self, view: str, path: Path, zone: str = RPZ) -> None:
        """What a reload of ``path`` would leave named holding."""
        self.zones[view] = _file_content(path, zone)


def _file_content(path: Path, zone: str = RPZ) -> set[tuple[str, str, str]]:
    origin = dns.name.from_text(zone)
    out: set[tuple[str, str, str]] = set()
    for line in path.read_text().splitlines()[3:]:
        if not line:
            continue
        owner, rtype, rdata = bind9._rpz_split(line)
        rd = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.from_text(rtype), rdata, origin
        )
        out.add((dns.name.from_text(owner, origin).to_text(), rtype, rd.to_text()))
    return out


@pytest.fixture
def named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Named:
    n = _Named(tmp_path)
    monkeypatch.setattr(subprocess, "run", n.run)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/sbin/rndc")
    monkeypatch.setattr(bind9.dns.query, "tcp", n.tcp)
    return n


def _driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Bind9Driver:
    drv = Bind9Driver(state_dir=tmp_path)
    monkeypatch.setattr(drv, "daemon_running", lambda: True)
    return drv


def _apply(drv: Bind9Driver, bundle: dict[str, Any]) -> None:
    drv.render(bundle)
    drv.swap_and_reload()


def _settled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named, bundle: dict[str, Any]
) -> Bind9Driver:
    """A driver that has applied ``bundle`` once, as named would have loaded it."""
    drv = _driver(tmp_path, monkeypatch)
    _apply(drv, bundle)
    live = tmp_path / "rendered"
    for rel in drv._rpz_update_keys:
        view = Path(rel).parent.name if Path(rel).parent.name != "zones" else ""
        key = f"spatium-view-{view}" if view else LOOPBACK["name"]
        named.zones[key] = _file_content(live / rel, _zone_of(rel))
    named.rndc.clear()
    return drv


def _zone_of(rel: str) -> str:
    return Path(rel).name.removesuffix(".db")


# ── The render ────────────────────────────────────────────────────────────────


def test_the_rpz_zone_takes_the_agents_key_and_updates_apply_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    drv = _driver(tmp_path, monkeypatch)
    _apply(drv, _flat([_bl(_names("a"))]))
    conf = (tmp_path / "rendered" / "named.conf").read_text()
    assert f'zone "{RPZ}" {{ type master;' in conf
    assert f'allow-update {{ key "{LOOPBACK["name"]}"; }};' in conf
    # named applies an update to its policy summary at most every 60 s unless
    # told otherwise: a blocked name must not stay open for a minute.
    assert f'zone "{RPZ.rstrip(".")}" min-update-interval 0' in conf


def test_a_bundle_without_a_key_leaves_the_zone_static(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    drv = _driver(tmp_path, monkeypatch)
    _apply(drv, _flat([_bl(_names("a"))], keys=False))
    conf = (tmp_path / "rendered" / "named.conf").read_text()
    assert "allow-update" not in conf
    assert "min-update-interval" not in conf
    assert drv._rpz_update_keys == {}


# ── Incremental apply ─────────────────────────────────────────────────────────


def test_a_small_change_is_sent_as_updates_and_the_zone_is_not_reloaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    old = _names("a")
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))
    new = old[3:] + ["fresh-one.example.test", "fresh-two.example.test"]

    _apply(drv, _flat([_bl(new)]))

    # Updates, signed with the agent's key, and not one verb that names the
    # zone: no freeze, reload or thaw, so no second copy in named.
    assert named.messages, "no update was sent"
    assert {m.keyname.to_text(omit_final_dot=True) for m in named.messages} == {"spatium-loopback"}
    assert not [c for c in named.rndc if "spatium-blocklist.rpz" in c], named.rndc
    # What named now holds is exactly the new render.
    live = tmp_path / "rendered" / RPZ_FILE
    assert named.zones["spatium-loopback"] == _file_content(live)
    # ...and the file on disk is the full new render too (restart-safe).
    assert "fresh-one.example.test CNAME ." in live.read_text()
    assert "a0000.example.test" not in live.read_text()


def test_the_next_change_diffs_against_what_the_last_update_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    old = _names("a")
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))
    second = old + ["two.example.test"]
    third = second + ["three.example.test"]
    _apply(drv, _flat([_bl(second)]))
    named.messages.clear()

    _apply(drv, _flat([_bl(third)]))

    sent = [rd.to_text() for m in named.messages for rr in m.update for rd in rr]
    # Only the third name travels, as its own CNAME (nothing of the first).
    assert [r for r in sent if r == "."] and len(sent) == 1
    assert named.zones["spatium-loopback"] == _file_content(tmp_path / "rendered" / RPZ_FILE)


def test_a_modified_entry_is_removed_before_it_is_added(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    """nxdomain -> sinkhole at one owner: the CNAME has to go before the
    addresses arrive, or named drops them (an address beside a CNAME)."""
    old = _names("a", 20)
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))
    bl = _bl(old)
    flip = next(i for i, e in enumerate(bl["entries"]) if e["block_mode"] == "nxdomain")
    bl["entries"][flip] = dict(bl["entries"][flip], block_mode="sinkhole")
    bl["rpz_sha256"] = "sha256:" + "f" * 64

    _apply(drv, _flat([bl]))

    ops = [("del" if rr.deleting == dns.rdataclass.NONE else "add") for m in named.messages for rr in m.update]
    assert "del" in ops and "add" in ops
    assert ops.index("add") > len(ops) - 1 - ops[::-1].index("del")
    assert named.zones["spatium-loopback"] == _file_content(tmp_path / "rendered" / RPZ_FILE)


def test_a_large_diff_falls_back_to_a_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    old = _names("a", 300)
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))

    _apply(drv, _flat([_bl(_names("b", 300))]))  # a list swap

    assert named.messages == []
    assert "spatium-blocklist.rpz" in named.verbs("reload")
    # The reloaded zone is verified like any other.
    assert "spatium-blocklist.rpz" in named.verbs("zonestatus")


def test_the_budget_is_a_tenth_of_the_zone_with_a_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    old = _names("a", 1000)
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))
    # 1000 names (+wildcards) -> ~1333 lines: 150 removals + 150 additions is
    # over a tenth; 20 + 20 is under it.
    _apply(drv, _flat([_bl(old[:850] + _names("n", 150))]))
    assert named.messages == []
    assert "spatium-blocklist.rpz" in named.verbs("reload")


def test_an_update_error_falls_back_to_the_full_render_and_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    old = _names("a")
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))
    named.rcode = dns.rcode.REFUSED

    _apply(drv, _flat([_bl(old + ["x.example.test"])]))

    assert "spatium-blocklist.rpz" in named.verbs("reload")
    live = tmp_path / "rendered" / RPZ_FILE
    assert "x.example.test CNAME ." in live.read_text()
    # The snapshot was dropped by the failure, then re-taken from the apply
    # that did load the zone: the next small change is incremental again.
    named.rcode = dns.rcode.NOERROR
    named.load("spatium-loopback", live)
    named.rndc.clear()
    _apply(drv, _flat([_bl(old + ["x.example.test", "y.example.test"])]))
    assert named.messages
    assert not [c for c in named.rndc if "spatium-blocklist.rpz" in c]


def test_an_update_named_ignores_is_caught_by_the_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    """NOERROR is also what named answers for an addition it cannot apply."""
    old = _names("a")
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))
    named.ignore_adds = True

    _apply(drv, _flat([_bl(old + ["x.example.test"])]))

    assert "spatium-blocklist.rpz" in named.verbs("reload")


def test_a_failed_apply_after_an_update_checks_the_zone_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    """named took the update, then the apply failed and was reverted: named
    holds content the reverted tree does not, so the zone is reloaded by the
    next apply rather than trusted."""
    old = _names("a")
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))

    def boom(*a: Any, **kw: Any) -> None:
        raise RuntimeError("named rejected the new config")

    monkeypatch.setattr(drv, "_signal_reload", boom)
    drv.render(_flat([_bl(old + ["x.example.test"])]))
    with pytest.raises(RuntimeError):
        drv.swap_and_reload()
    assert named.messages  # it was sent

    monkeypatch.undo()
    monkeypatch.setattr(subprocess, "run", named.run)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/sbin/rndc")
    monkeypatch.setattr(bind9.dns.query, "tcp", named.tcp)
    monkeypatch.setattr(drv, "daemon_running", lambda: True)
    named.messages.clear()
    named.rndc.clear()
    _apply(drv, _flat([_bl(old)]))  # the revert's render

    assert named.messages == []
    assert "spatium-blocklist.rpz" in named.verbs("reload")


# ── Named's own dump ──────────────────────────────────────────────────────────


def test_a_dump_over_the_live_file_does_not_make_an_unchanged_zone_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    """named writes a dynamic zone over its file within ~15 minutes of an
    update, in its own format. The next structural apply must still see the
    list as unchanged (snapshot), not reload 350k names for it."""
    old = _names("a")
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))
    live = tmp_path / "rendered" / RPZ_FILE
    live.unlink()
    live.write_text("rpz.local. 60 IN SOA localhost. root.localhost. 7 3600 600 86400 60\n")
    bl = _bl(old)  # same list, same hash

    _apply(drv, _flat([bl, _bl(["other.example.test"], zone="other.rpz.")]))

    assert named.messages == []
    assert "spatium-blocklist.rpz" not in {z for c in named.rndc for z in c}
    # The file named serves is ours again, from the snapshot.
    assert "a0000.example.test CNAME ." in (tmp_path / "rendered" / RPZ_FILE).read_text()


# ── Views ─────────────────────────────────────────────────────────────────────


def test_each_view_gets_its_own_diff_signed_with_its_own_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    internal = "spatium-blocklist-internal.rpz."
    external = "spatium-blocklist-external.rpz."
    a, b = _names("a"), _names("b")
    drv = _settled(
        tmp_path,
        monkeypatch,
        named,
        _views([_bl(a, zone=internal, view="internal"), _bl(b, zone=external, view="external")]),
    )

    _apply(
        drv,
        _views(
            [
                _bl(a + ["only-internal.example.test"], zone=internal, view="internal"),
                _bl(b[1:], zone=external, view="external"),
            ]
        ),
    )

    by_key: dict[str, list[str]] = {}
    for m in named.messages:
        by_key.setdefault(m.keyname.to_text(omit_final_dot=True), []).extend(
            rr.name.to_text() for rr in m.update
        )
    assert set(by_key) == {"spatium-view-internal", "spatium-view-external"}
    assert any("only-internal" in n for n in by_key["spatium-view-internal"])
    assert not any("only-internal" in n for n in by_key["spatium-view-external"])
    assert not [c for c in named.rndc if "rpz" in " ".join(c)], named.rndc
    live = tmp_path / "rendered" / "zones"
    assert named.zones["spatium-view-internal"] == _file_content(
        live / "internal" / f"{internal}db", internal
    )
    assert named.zones["spatium-view-external"] == _file_content(
        live / "external" / f"{external}db", external
    )


def test_a_view_without_a_transfer_key_stays_static(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    bundle = _views([_bl(_names("a"), zone="spatium-blocklist-internal.rpz.", view="internal")])
    bundle["views"][0].pop("transfer_key")
    drv = _driver(tmp_path, monkeypatch)
    _apply(drv, bundle)
    assert "allow-update" not in (tmp_path / "rendered" / "named.conf").read_text()
    assert drv._rpz_update_keys == {}


# ── Snapshot housekeeping ─────────────────────────────────────────────────────


def test_the_snapshot_follows_the_live_zone_and_is_dropped_with_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(_names("a"))]))
    snap = tmp_path / "rpz-applied" / RPZ_FILE
    live = tmp_path / "rendered" / RPZ_FILE
    assert snap.read_bytes() == live.read_bytes()
    assert snap.stat().st_ino == live.stat().st_ino  # a link, not a second copy

    _apply(drv, _flat([]))  # the list is gone

    assert not snap.exists()
    assert not snap.with_name(snap.name + ".sha256").exists()


def test_a_sighup_fallback_does_not_vouch_for_what_named_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    """Without rndc nothing is verified and SIGHUP re-reads no dynamic zone's
    file, so the next apply must not diff against a snapshot of the render
    named may never have loaded."""
    old = _names("a")
    drv = _settled(tmp_path, monkeypatch, named, _flat([_bl(old)]))
    monkeypatch.setattr(drv, "_signal_reload", lambda *a, **kw: False)
    _apply(drv, _flat([_bl(old + ["x.example.test"])]))
    monkeypatch.undo()
    monkeypatch.setattr(subprocess, "run", named.run)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/sbin/rndc")
    monkeypatch.setattr(bind9.dns.query, "tcp", named.tcp)
    monkeypatch.setattr(drv, "daemon_running", lambda: True)
    named.messages.clear()
    named.rndc.clear()

    _apply(drv, _flat([_bl(old + ["x.example.test", "y.example.test"])]))

    assert named.messages == []
    assert "spatium-blocklist.rpz" in named.verbs("reload")


# ── Duplicate lines ───────────────────────────────────────────────────────────


def test_a_wildcard_owner_is_rendered_once_however_many_entries_name_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, named: _Named
) -> None:
    """``adonweb.ru`` (wildcard) and an explicit ``*.adonweb.ru`` both own
    ``*.adonweb.ru``; the renderer wrote its lines twice."""
    drv = _driver(tmp_path, monkeypatch)
    bl = _bl(["adonweb.ru", "*.adonweb.ru", "other.example.test"])
    bl["entries"][0]["is_wildcard"] = True
    bl["entries"][1]["is_wildcard"] = False
    _apply(drv, _flat([bl]))
    lines = (tmp_path / "rendered" / RPZ_FILE).read_text().splitlines()
    assert lines.count("*.adonweb.ru CNAME .") == 1


def test_duplicate_lines_do_not_count_as_changes(tmp_path: Path) -> None:
    """A file that repeats lines (an older render, a hand edit): +2 / -3 is
    exactly 2 adds and 3 removes, repeats neither re-sent nor counted."""
    head = "$TTL 60\n@ IN SOA localhost. root.localhost. ( 1 3600 600 86400 60 )\n@ IN NS localhost.\n"
    base = [f"n{i}.example.test CNAME ." for i in range(200)]
    old = base + base[:10] + base[:3]  # ten lines twice, three of them thrice
    new_lines = base[3:] + ["x.example.test CNAME .", "y.example.test CNAME ."]
    new = new_lines + new_lines[:10]
    (tmp_path / "old.db").write_text(head.replace("( 1 ", "( 1 ") + "\n".join(old) + "\n")
    (tmp_path / "new.db").write_text(head.replace("( 1 ", "( 2 ") + "\n".join(new) + "\n")

    diff = bind9._rpz_diff(tmp_path / "old.db", tmp_path / "new.db")

    assert diff is not None
    assert sorted(diff.adds) == ["x.example.test CNAME .", "y.example.test CNAME ."]
    assert sorted(diff.removes) == [f"n{i}.example.test CNAME ." for i in range(3)]
