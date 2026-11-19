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
import io
import os
import socket
import threading

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


@pytest.mark.parametrize(
    "field",
    [
        "sftp.example,!sftp.example",
        "sftp.example,!*.example",
        "SFTP.example,!sftp.EXAMPLE",
        "[sftp.example]:2222,![sftp.example]:2222",
    ],
)
def test_a_negation_that_covers_a_name_on_its_line_withholds_it(field: str) -> None:
    # OpenSSH never matches a host a negated pattern on the line matches.
    # Dropping only the ``!`` entry would pin the name it was there to
    # exclude.
    keytype, b64 = _pub()
    hk = _load(f"{field} {keytype} {b64}\n").get_host_keys()
    for name in field.split(","):
        if not name.startswith("!"):
            assert hk.lookup(name) is None, name


def test_a_revoked_key_is_matched_by_blob_not_by_spelling() -> None:
    # The pin carries a character the base64 decoder discards, so the two
    # lines differ as strings and still name the same key.
    keytype, b64 = _pub()
    respelled = b64[:20] + "\x00" + b64[20:]
    assert (
        _load(f"sftp.example {keytype} {respelled}\n").get_host_keys().lookup("sftp.example")
    )  # control: the respelled pin is a working pin on its own
    text = f"sftp.example {keytype} {respelled}\n@revoked * {keytype} {b64}\n"
    assert _load(text).get_host_keys().lookup("sftp.example") is None


# --- the connect path: a real SSH handshake against an in-process server ---


class _Server(paramiko.ServerInterface):
    def check_auth_password(self, username: str, password: str) -> int:
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return "password"


@pytest.fixture
def ssh_server():  # type: ignore[no-untyped-def]
    host_key = paramiko.Ed25519Key.from_private_key(
        io.StringIO(
            ed25519.Ed25519PrivateKey.generate()
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            )
            .decode()
        )
    )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    sock.settimeout(10)
    transports: list[paramiko.Transport] = []

    def serve() -> None:
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(host_key)
            transports.append(t)
            try:
                t.start_server(server=_Server())
            except Exception:  # noqa: BLE001 — the client refused the key
                continue

    threading.Thread(target=serve, daemon=True).start()
    yield sock.getsockname()[1], f"{host_key.get_name()} {host_key.get_base64()}"
    sock.close()
    for t in transports:
        t.close()


def _connect(port: int, known_hosts: str):  # type: ignore[no-untyped-def]
    from app.services.backup.targets.scp import ScpDestination

    return ScpDestination()._connect(  # noqa: SLF001
        {
            "host": "127.0.0.1",
            "port": port,
            "username": "u",
            "password": "p",
            "remote_path": "/x",
            "known_hosts": known_hosts,
        }
    )


def test_connect_accepts_a_host_ip_list_pin(ssh_server) -> None:  # type: ignore[no-untyped-def]
    port, key = ssh_server
    _connect(port, f"[sftp.example]:{port},[127.0.0.1]:{port} {key}\n").close()


@pytest.mark.parametrize(
    "known",
    [
        "* {key}\n",
        "*:{port} {key}\n[*]:{port} {key}\n",
        "@cert-authority * {key}\n",
        "[127.0.0.1]:{port},![127.0.0.1]:{port} {key}\n",
        "[127.0.0.1]:{port} {key}\n@revoked * {key}\n",
        "# nothing pinned\n",
    ],
)
def test_connect_refuses_when_nothing_pins_the_host(ssh_server, known: str) -> None:  # type: ignore[no-untyped-def]
    # An empty or unusable store must be a refusal (RejectPolicy), never
    # an accept-any.
    from app.services.backup.targets.base import BackupDestinationError

    port, key = ssh_server
    with pytest.raises(BackupDestinationError, match="not found in known_hosts"):
        _connect(port, known.format(key=key, port=port))
