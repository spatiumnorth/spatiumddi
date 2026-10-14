"""DS computed in-process from a KSK .key file (#1854): no dnssec-dsfromkey."""

from __future__ import annotations

import base64
import hashlib
import struct
from pathlib import Path

from spatium_dns_agent.drivers.bind9 import _ds_from_key_dir

PUB = base64.b64encode(bytes(range(64))).decode()


def _write(d: Path, zone: str, flags: int, tag: int = 12345) -> None:
    (d / f"K{zone}.+013+{tag:05d}.key").write_text(
        f"; This is a key-signing key\n{zone}. 3600 IN DNSKEY {flags} 3 13 {PUB}\n"
    )


def test_ds_for_ksk_matches_rfc4034_digest(tmp_path: Path) -> None:
    _write(tmp_path, "example.test", 257)
    _write(tmp_path, "example.test", 256, tag=999)  # ZSK ignored
    out = _ds_from_key_dir("example.test", str(tmp_path))
    assert len(out) == 1
    owner, cls, typ, tag, alg, dt, digest = out[0].split()
    assert (owner, cls, typ, alg, dt) == ("example.test.", "IN", "DS", "13", "2")
    wire_name = b"\x07example\x04test\x00"
    rdata = struct.pack("!HBB", 257, 3, 13) + base64.b64decode(PUB)
    assert digest == hashlib.sha256(wire_name + rdata).hexdigest().upper()
    assert int(tag) > 0


def test_missing_ksk_is_logged_not_silent(tmp_path: Path, capsys) -> None:
    _write(tmp_path, "example.test", 256)
    assert _ds_from_key_dir("example.test", str(tmp_path)) == []
    cap = capsys.readouterr()
    assert "dnssec_ds_unavailable" in cap.out + cap.err


def test_missing_dir_is_logged(tmp_path: Path, capsys) -> None:
    assert _ds_from_key_dir("example.test", str(tmp_path / "nope")) == []
    cap = capsys.readouterr()
    assert "key_dir_missing" in cap.out + cap.err
