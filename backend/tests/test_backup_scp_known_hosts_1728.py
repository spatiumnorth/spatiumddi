"""SCP backup target: known_hosts host-field forms (#1728).

``_load_supplied_host_keys`` passed the whole first field to paramiko's
``HostKeys.add`` as ONE name, so ``host,ip`` (what OpenSSH before 8.5 wrote
to ``~/.ssh/known_hosts`` by default) matched neither name. These load
lines through the real loader and look names up in the real store.
Verification must also never fail open: markers and patterns this store
cannot honour must leave the host unmatched.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.services.backup.targets.scp import _load_supplied_host_keys


def _pub() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    line = (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    keytype, b64 = line.split()
    return keytype, b64


def _load(text: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    _load_supplied_host_keys(client, text)
    return client


def test_host_and_ip_list_matches_both_names() -> None:
    keytype, b64 = _pub()
    hk = _load(f"sftp.example,192.0.2.10 {keytype} {b64}\n").get_host_keys()
    for name in ("sftp.example", "192.0.2.10"):
        found = hk.lookup(name)
        assert found is not None, f"{name} not matched"
        assert found[keytype].get_base64() == b64
    assert hk.lookup("other.example") is None


def test_bracketed_port_entries_in_a_list() -> None:
    keytype, b64 = _pub()
    hk = _load(f"[sftp.example]:2222,[192.0.2.10]:2222 {keytype} {b64}\n").get_host_keys()
    assert hk.lookup("[sftp.example]:2222") is not None
    assert hk.lookup("[192.0.2.10]:2222") is not None
    assert hk.lookup("sftp.example") is None


def test_hashed_host_still_matches() -> None:
    keytype, b64 = _pub()
    salt = os.urandom(20)
    digest = hmac.new(salt, b"sftp.example", hashlib.sha1).digest()
    hashed = "|1|" + base64.b64encode(salt).decode() + "|" + base64.b64encode(digest).decode()
    hk = _load(f"{hashed} {keytype} {b64}\n").get_host_keys()
    assert hk.lookup("sftp.example") is not None
    assert hk.lookup("other.example") is None


def test_cert_authority_line_does_not_pin_a_host_key() -> None:
    keytype, b64 = _pub()
    hk = _load(f"@cert-authority sftp.example {keytype} {b64}\n").get_host_keys()
    assert hk.lookup("sftp.example") is None
    assert hk.lookup("@cert-authority") is None


def test_revoked_key_is_refused_even_when_pinned_elsewhere() -> None:
    keytype, b64 = _pub()
    text = f"sftp.example {keytype} {b64}\n@revoked * {keytype} {b64}\n"
    assert _load(text).get_host_keys().lookup("sftp.example") is None


def test_revoking_one_key_leaves_a_different_pin() -> None:
    keytype, b64 = _pub()
    _, other = _pub()
    text = f"@revoked * {keytype} {other}\nsftp.example {keytype} {b64}\n"
    assert _load(text).get_host_keys().lookup("sftp.example") is not None


@pytest.mark.parametrize("field", ["*", "*.example", "sftp.?xample", "!sftp.example"])
def test_patterns_this_store_cannot_honour_match_nothing(field: str) -> None:
    keytype, b64 = _pub()
    hk = _load(f"{field} {keytype} {b64}\n").get_host_keys()
    assert hk.lookup("sftp.example") is None
    assert hk.lookup("anything.example") is None


def test_negated_name_in_a_list_is_not_added() -> None:
    keytype, b64 = _pub()
    hk = _load(f"sftp.example,!bad.example {keytype} {b64}\n").get_host_keys()
    assert hk.lookup("sftp.example") is not None
    assert hk.lookup("bad.example") is None


@pytest.mark.parametrize("line", ["sftp.example,", ",", "sftp.example ssh-ed25519", "@revoked", ""])
def test_malformed_lines_pin_nothing(line: str) -> None:
    assert _load(line + "\n").get_host_keys().lookup("sftp.example") is None
