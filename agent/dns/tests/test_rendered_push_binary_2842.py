"""Binary BIND companions are not pushed in the rendered-config snapshot (#2842)."""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.admin_pusher import _walk_rendered


def test_nul_files_and_journals_are_not_walked(tmp_path: Path) -> None:
    (tmp_path / "named.conf").write_text("options { };\n")
    (tmp_path / "zones").mkdir()
    (tmp_path / "zones" / "example.com.db").write_text("@ IN SOA a. b. ( 1 2 3 4 5 )\n")
    # NUL bytes decode as valid UTF-8, so only the NUL check can catch this.
    (tmp_path / "zones" / "example.com.db.state").write_bytes(b"BIND\x00\x01data")
    (tmp_path / "zones" / "example.com.db.jnl").write_bytes(b"\x00journal")
    (tmp_path / "zones" / "example.com.db.signed").write_bytes(b"\x00signed")

    paths = [rel for rel, _ in _walk_rendered(tmp_path)]

    assert paths == ["named.conf", "zones/example.com.db"]
