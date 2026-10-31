"""#2309: key files of zones no longer signed are aged out after a good apply."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.cache import commit_config, ensure_layout, save_config
from spatium_dns_agent.drivers import bind9 as b9
from spatium_dns_agent.drivers.bind9 import Bind9Driver, _ds_from_key_dir

from .test_config_revert import _bundle, _Driver, _loop

GRACE = 1000.0


def _keys(d: Path, zone: str, tag: int = 1) -> None:
    for ext in ("key", "private", "state"):
        (d / f"K{zone.rstrip('.')}.+013+{tag:05d}.{ext}").write_text("x")


@pytest.fixture
def keydir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "keys"
    d.mkdir()
    monkeypatch.setattr(b9, "DNSSEC_KEY_DIR", str(d))
    monkeypatch.setattr(b9, "DNSSEC_KEY_PRUNE_GRACE_SECONDS", GRACE)
    return d


def _driver(tmp_path: Path) -> Bind9Driver:
    drv = Bind9Driver.__new__(Bind9Driver)
    drv.state_dir = tmp_path
    return drv


def _z(name: str, signed: bool = True, **kw: Any) -> dict[str, Any]:
    return {"name": name, "dnssec_enabled": signed, "type": "primary", **kw}


def _left(d: Path) -> set[str]:
    return {p.name for p in d.iterdir()}


def test_unsigned_zone_keys_survive_the_grace_period_then_go(tmp_path, keydir):
    _keys(keydir, "gone.test.")
    _keys(keydir, "unsigned.test.")
    _keys(keydir, "kept.test.")
    drv = _driver(tmp_path)
    bundle = {"zones": [_z("kept.test."), _z("unsigned.test.", False)]}

    assert drv.prune_dnssec_keys(bundle, now=100.0) == []
    assert len(_left(keydir)) == 9
    # Still inside the window: nothing yet.
    assert drv.prune_dnssec_keys(bundle, now=100.0 + GRACE - 1) == []
    assert len(_left(keydir)) == 9

    removed = drv.prune_dnssec_keys(bundle, now=100.0 + GRACE)
    assert len(removed) == 6
    assert _left(keydir) == {
        f"Kkept.test.+013+00001.{e}" for e in ("key", "private", "state")
    }
    # Nothing pending any more.
    assert json.loads((tmp_path / b9.DNSSEC_KEY_PRUNE_STATE).read_text()) == {}


def test_resigning_inside_the_window_keeps_the_keys(tmp_path, keydir):
    """An accidental unsign / delete undone within the grace period keeps the
    keys whose DS the parent already has — and restarts the clock."""
    _keys(keydir, "oops.test.")
    drv = _driver(tmp_path)
    drv.prune_dnssec_keys({"zones": []}, now=0.0)
    drv.prune_dnssec_keys({"zones": [_z("OOPS.test")]}, now=GRACE / 2)
    # Unsigned again: a fresh window, not the remainder of the old one.
    drv.prune_dnssec_keys({"zones": []}, now=GRACE)
    assert drv.prune_dnssec_keys({"zones": []}, now=GRACE * 1.5) == []
    assert len(_left(keydir)) == 3
    assert len(drv.prune_dnssec_keys({"zones": []}, now=GRACE * 2)) == 3


def test_zero_grace_deletes_at_once(tmp_path, keydir, monkeypatch):
    monkeypatch.setattr(b9, "DNSSEC_KEY_PRUNE_GRACE_SECONDS", 0.0)
    _keys(keydir, "back.test.", tag=7)
    assert len(_driver(tmp_path).prune_dnssec_keys({"zones": []}, now=5.0)) == 3
    assert _left(keydir) == set()


def test_unreadable_state_restarts_the_clock(tmp_path, keydir):
    _keys(keydir, "x.test.")
    drv = _driver(tmp_path)
    drv.prune_dnssec_keys({"zones": []}, now=0.0)
    (tmp_path / b9.DNSSEC_KEY_PRUNE_STATE).write_text("{not json")
    assert drv.prune_dnssec_keys({"zones": []}, now=GRACE * 5) == []
    assert len(_left(keydir)) == 3


def test_clock_going_backwards_does_not_shorten_the_window(tmp_path, keydir):
    _keys(keydir, "x.test.")
    drv = _driver(tmp_path)
    drv.prune_dnssec_keys({"zones": []}, now=10_000.0)
    assert drv.prune_dnssec_keys({"zones": []}, now=5.0) == []
    assert drv.prune_dnssec_keys({"zones": []}, now=5.0 + GRACE - 1) == []
    assert len(_left(keydir)) == 3


def test_name_prefix_collision_is_safe(tmp_path, keydir, monkeypatch):
    monkeypatch.setattr(b9, "DNSSEC_KEY_PRUNE_GRACE_SECONDS", 0.0)
    _keys(keydir, "sub.example.com.")
    _keys(keydir, "example.com.")
    drv = _driver(tmp_path)
    drv.prune_dnssec_keys({"zones": [_z("sub.example.com")]})
    assert len(_left(keydir)) == 3
    assert all(n.startswith("Ksub.example.com.") for n in _left(keydir))
    _keys(keydir, "example.com.")
    drv.prune_dnssec_keys({"zones": [_z("Example.COM.")]})
    assert len(_left(keydir)) == 3
    assert not any(n.startswith("Ksub.") for n in _left(keydir))


def test_classless_reverse_zone_filename_is_decoded(tmp_path, keydir, monkeypatch):
    """BIND writes ``/`` in a zone name as ``%2F`` (verified on named 9.20):
    ``K0%2F26.2.0.192.in-addr.arpa.+013+…``. Compared undecoded, a signed
    RFC 2317 zone's live keys read as an unknown zone's and were deleted."""
    monkeypatch.setattr(b9, "DNSSEC_KEY_PRUNE_GRACE_SECONDS", 0.0)
    _keys(keydir, "0%2F26.2.0.192.in-addr.arpa.")
    drv = _driver(tmp_path)
    assert drv.prune_dnssec_keys({"zones": [_z("0/26.2.0.192.in-addr.arpa.")]}) == []
    assert len(_left(keydir)) == 3
    assert b9._key_zone("K0%2F26.2.0.192.in-addr.arpa.+013+34065.key") == (
        "0/26.2.0.192.in-addr.arpa"
    )


def test_ds_lookup_matches_encoded_and_mixed_case_names(tmp_path):
    """The DS reader keyed on ``K{zone}.+`` verbatim, so it found no key for a
    classless reverse zone or a zone configured in mixed case."""
    pub = base64.b64encode(bytes(range(64))).decode()
    for zone, fname in (
        ("0/26.2.0.192.in-addr.arpa", "K0%2F26.2.0.192.in-addr.arpa.+013+11111.key"),
        ("Example.COM", "Kexample.com.+013+22222.key"),
    ):
        d = tmp_path / fname
        d.mkdir()
        (d / fname).write_text(f"{zone.lower()}. 3600 IN DNSKEY 257 3 13 {pub}\n")
        assert len(_ds_from_key_dir(zone, str(d))) == 1, zone


def test_zone_signed_in_either_view_keeps_keys(tmp_path, keydir, monkeypatch):
    monkeypatch.setattr(b9, "DNSSEC_KEY_PRUNE_GRACE_SECONDS", 0.0)
    _keys(keydir, "split.test.")
    _driver(tmp_path).prune_dnssec_keys(
        {
            "zones": [
                _z("split.test.", True, view="a"),
                _z("split.test.", False, view="b"),
            ]
        }
    )
    assert len(_left(keydir)) == 3


def test_symlinks_and_foreign_files_are_left_alone(tmp_path, keydir, monkeypatch):
    monkeypatch.setattr(b9, "DNSSEC_KEY_PRUNE_GRACE_SECONDS", 0.0)
    target = tmp_path / "elsewhere"
    target.write_text("x")
    (keydir / "Klink.test.+013+00001.private").symlink_to(target)
    (keydir / "README").write_text("x")
    _driver(tmp_path).prune_dnssec_keys({"zones": []})
    assert _left(keydir) == {"Klink.test.+013+00001.private", "README"}
    assert target.exists()


# ── SyncLoop: prune only on a bundle that applied ─────────────────────────


class _PruneDriver(_Driver):
    def __init__(self, state_dir: Path):
        super().__init__(state_dir)
        self.pruned: list[set[str]] = []

    def prune_dnssec_keys(self, bundle: dict[str, Any]) -> list[str]:
        self.pruned.append(
            {z["name"] for z in bundle["zones"] if z.get("dnssec_enabled")}
        )
        return []


def _signed(tag: str, *zones: str) -> dict[str, Any]:
    return {**_bundle(tag), "zones": [_z(z) for z in zones] + [_z("plain.test", False)]}


def test_failed_apply_never_prunes_and_pauses_periodic_pruning(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    driver = _PruneDriver(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")
    loop = _loop(tmp_path, driver)
    # Booting from the committed cache is itself a good apply.
    assert driver.pruned == [set()]
    driver.pruned.clear()

    assert loop._apply_with_revert(_signed("one", "a.test"), "one") is True
    assert driver.pruned == [{"a.test"}]

    # The periodic re-check reuses the applied bundle's signed set.
    loop._prune_dnssec_keys()
    assert driver.pruned[-1] == {"a.test"}

    for phase in ("render", "validate", "reload"):
        driver.pruned.clear()
        driver.fail_on = phase
        assert loop._apply_with_revert(_bundle(f"bad-{phase}"), f"bad-{phase}") is False
        assert driver.pruned == [], phase
        # …and the periodic call does nothing until a bundle applies again.
        loop._prune_dnssec_keys()
        assert driver.pruned == [], phase

    driver.fail_on = None
    assert loop._apply_with_revert(_signed("two", "b.test"), "two") is True
    assert driver.pruned == [{"b.test"}]


def test_prune_failure_does_not_fail_the_apply(tmp_path: Path) -> None:
    ensure_layout(tmp_path)

    class _Boom(_Driver):
        def prune_dnssec_keys(self, bundle: dict[str, Any]) -> list[str]:
            raise OSError("read-only file system")

    loop = _loop(tmp_path, _Boom(tmp_path))
    assert loop._apply_with_revert(_signed("one", "a.test"), "one") is True


def _polled(tag: str, structural: str, *signed: str) -> dict[str, Any]:
    return {
        "etag": tag,
        "structural_etag": structural,
        "zones": [_z(z) for z in signed],
        "pending_record_ops": [],
    }


def test_key_cleanup_resumes_after_a_recovered_config(tmp_path: Path, monkeypatch) -> None:
    """A failed apply clears the prune set. Undoing the bad change leaves the
    live structure unchanged, so the poll takes the recovery path and no
    structural apply follows: cleanup must still resume from that poll."""
    from spatium_dns_agent.sync import STATUS_OK
    from .test_config_revert import _Http

    ensure_layout(tmp_path)
    monkeypatch.setattr("spatium_dns_agent.sync.push_rendered_config", lambda *a: None)
    driver = _PruneDriver(tmp_path)
    loop = _loop(tmp_path, driver)
    http = _Http(
        [
            _polled("e1", "s1", "a.test"),
            _polled("e2", "s2", "a.test", "b.test"),
            _polled("e3", "s1", "a.test"),
        ]
    )
    loop._client = lambda: http  # type: ignore[method-assign]

    loop._poll_once()
    assert driver.pruned[-1] == {"a.test"}
    driver.pruned.clear()

    driver.fail_on = "render"
    loop._poll_once()
    assert not loop.apply_status.healthy
    assert driver.pruned == []
    assert loop._key_prune_bundle is None

    # The operator undoes the change: same structure as what is live.
    driver.fail_on = None
    loop._poll_once()
    assert loop.apply_status.status == STATUS_OK
    assert driver.pruned == [{"a.test"}]
    assert loop._key_prune_bundle is not None

    # And the periodic check is armed again.
    driver.pruned.clear()
    loop._prune_dnssec_keys()
    assert driver.pruned == [{"a.test"}]
