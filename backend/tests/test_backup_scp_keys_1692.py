"""SCP / SFTP backup target: real keys through the driver (#1692).

paramiko 4.0 removed DSA support, ``paramiko.DSSKey`` included, and the
backend pins ``paramiko>=3.4.0`` with no upper bound, so the image installs
the newest (5.x). The driver still named ``paramiko.DSSKey`` in two places
that run on every connect:

* ``_decode_pubkey`` built its key-type map with it, before the lookup, so
  every known_hosts line raised ``AttributeError``. The caller skips a line
  that raises, the host-key store stayed empty, and the checked modes
  (``known_hosts``, the default, and ``strict``) refused every server as
  "not found in known_hosts", even one whose key was pinned.
* ``_load_private_key`` listed it among the key classes it tries, and the
  tuple is built before any key is tried. The ``AttributeError`` is not the
  ``SSHException`` the loop catches, ``_connect`` calls the loader outside
  its ``try``, and Test connection answered a 500.

No test loaded a real key through either function, so CI stayed green on
paramiko 5. These do, with whatever paramiko is installed: every key is
made at run time, and the host-key cases complete a real SSH handshake
against an in-process paramiko server on 127.0.0.1. A paramiko that drops
another key class, or changes how one loads, fails here.
"""

from __future__ import annotations

import contextlib
import io
import socket
import threading
from collections.abc import Iterator
from typing import Any

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from app.services.backup.targets.base import BackupDestinationError
from app.services.backup.targets.scp import (
    ScpDestination,
    _load_private_key,
    _load_supplied_host_keys,
)

KINDS = ("ed25519", "ecdsa", "rsa")
_USER = "backup"
_PASSWORD = "backup-pw-1692"


def _private_key(kind: str) -> Any:
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if kind == "ecdsa":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem(key: Any, *, fmt: str = "openssh", passphrase: str | None = None) -> str:
    """The key as ``ssh-keygen`` writes it (``openssh``), or as an older
    ssh-keygen or ``openssl`` writes RSA and EC keys (``traditional``)."""
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    private_format = (
        serialization.PrivateFormat.OpenSSH
        if fmt == "openssh"
        else serialization.PrivateFormat.TraditionalOpenSSL
    )
    return key.private_bytes(serialization.Encoding.PEM, private_format, encryption).decode()


def _public_line(key: Any) -> str:
    """``<type> <base64>``, as in ``ssh-keyscan`` output and authorized_keys."""
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )


def _host_key(kind: str) -> tuple[paramiko.PKey, str]:
    """A server host key (paramiko's, for the in-process server) and its
    public ``<type> <base64>`` as ``ssh-keyscan`` prints it."""
    key = _private_key(kind)
    cls = {"ed25519": paramiko.Ed25519Key, "ecdsa": paramiko.ECDSAKey, "rsa": paramiko.RSAKey}[kind]
    return cls.from_private_key(io.StringIO(_pem(key))), _public_line(key)


def _config(port: int, **extra: Any) -> dict[str, Any]:
    return {
        "host": "127.0.0.1",
        "port": str(port),
        "username": _USER,
        "remote_path": "/srv/backups",
        **extra,
    }


def _closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _Server(paramiko.ServerInterface):
    def __init__(self, user_key: paramiko.PKey | None) -> None:
        self.user_key = user_key

    def get_allowed_auths(self, username: str) -> str:
        return "publickey,password"

    def check_auth_password(self, username: str, password: str) -> int:
        if (username, password) == (_USER, _PASSWORD):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if username == _USER and self.user_key is not None and key == self.user_key:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED


@contextlib.contextmanager
def _ssh_server(host_key: paramiko.PKey, user_key: paramiko.PKey | None = None) -> Iterator[int]:
    """One SSH connection's worth of server on 127.0.0.1; yields its port."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    transports: list[paramiko.Transport] = []

    def serve() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        transport = paramiko.Transport(conn)
        transports.append(transport)
        transport.add_server_key(host_key)
        with contextlib.suppress(paramiko.SSHException, EOFError, OSError):
            transport.start_server(server=_Server(user_key))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()
        for transport in transports:
            transport.close()
        thread.join(timeout=5)


# ── known_hosts lines load ──────────────────────────────────────────────


@pytest.mark.parametrize("kind", KINDS)
def test_a_known_hosts_line_is_loaded_into_the_host_key_store(kind: str) -> None:
    key = _private_key(kind)
    keytype, b64 = _public_line(key).split()
    client = paramiko.SSHClient()

    _load_supplied_host_keys(client, f"[sftp.example]:2222 {keytype} {b64}\n")

    pinned = client.get_host_keys().lookup("[sftp.example]:2222")
    assert pinned is not None, f"the {keytype} line was not loaded: the host-key store is empty"
    assert pinned[keytype].get_base64() == b64


def test_every_line_of_ssh_keyscan_output_is_loaded() -> None:
    lines = [f"sftp.example {_public_line(_private_key(kind))}" for kind in KINDS]
    keyscan = "# sftp.example:22 SSH-2.0-OpenSSH_9.6\n" + "\n".join(lines) + "\n"
    client = paramiko.SSHClient()

    _load_supplied_host_keys(client, keyscan)

    pinned = client.get_host_keys().lookup("sftp.example")
    assert pinned is not None, "no line of the ssh-keyscan output was loaded"
    assert sorted(pinned.keys()) == sorted(line.split()[1] for line in lines)


@pytest.mark.parametrize(
    "unusable",
    [
        # DSA: no DSSKey in paramiko 4.0+. A real key blob prefix.
        "ssh-dss AAAAB3NzaC1kc3MAAACBAP",
        # FIDO security-key type the driver does not decode.
        "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t",
        # Not base64 at all.
        "ssh-ed25519 !!!not-base64",
    ],
)
def test_an_unusable_line_does_not_drop_a_valid_pin_for_the_same_host(unusable: str) -> None:
    # The unusable line used to be stored with a None key, and paramiko's
    # HostKeys.add / lookup call get_name() on every entry for the host,
    # so the valid line after it raised and was skipped too.
    key = _private_key("ed25519")
    keytype, b64 = _public_line(key).split()
    client = paramiko.SSHClient()

    _load_supplied_host_keys(
        client, f"[sftp.example]:2222 {unusable}\n[sftp.example]:2222 {keytype} {b64}\n"
    )

    store = client.get_host_keys()
    pinned = store.lookup("[sftp.example]:2222")
    assert pinned is not None
    assert list(pinned.keys()) == [keytype]
    assert store.check("[sftp.example]:2222", paramiko.Ed25519Key(data=pinned[keytype].asbytes()))


# ── private keys load ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("kind", "fmt"),
    [
        ("ed25519", "openssh"),
        ("ecdsa", "openssh"),
        ("rsa", "openssh"),
        ("ecdsa", "traditional"),
        ("rsa", "traditional"),
    ],
)
def test_a_private_key_is_loaded(kind: str, fmt: str) -> None:
    key = _private_key(kind)

    loaded = _load_private_key(_pem(key, fmt=fmt), None)

    assert f"{loaded.get_name()} {loaded.get_base64()}" == _public_line(key)


def test_a_passphrase_protected_private_key_is_loaded() -> None:
    key = _private_key("ed25519")

    loaded = _load_private_key(_pem(key, passphrase="correct horse"), "correct horse")

    assert f"{loaded.get_name()} {loaded.get_base64()}" == _public_line(key)


def test_text_that_is_no_private_key_is_a_destination_error() -> None:
    with pytest.raises(BackupDestinationError, match="could not parse private key"):
        _load_private_key("-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n", None)


def _dsa_openssh_pem() -> str:
    import warnings

    from cryptography.hazmat.primitives.asymmetric import dsa

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # cryptography deprecates SSH DSA
        return _pem(dsa.generate_private_key(key_size=1024))


def test_an_openssh_format_dsa_key_is_a_destination_error_not_a_crash() -> None:
    # RSAKey does not check the type inside an OpenSSH container, so the DSA
    # numbers reach cryptography as RSA and it raises ValueError. That is not
    # an SSHException, and it escaped Test connection as a 500.
    with pytest.raises(BackupDestinationError, match="DSA is not supported"):
        _load_private_key(_dsa_openssh_pem(), None)


def test_a_pkcs8_key_is_refused_with_how_to_convert_it() -> None:
    pem = (
        _private_key("ed25519")
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(BackupDestinationError, match="PKCS#8.*ssh-keygen -p"):
        _load_private_key(pem, None)


@pytest.mark.parametrize(("kind", "fmt"), [("ed25519", "openssh"), ("ecdsa", "traditional")])
def test_an_encrypted_key_with_no_passphrase_says_so(kind: str, fmt: str) -> None:
    pem = _pem(_private_key(kind), fmt=fmt, passphrase="correct horse")
    with pytest.raises(BackupDestinationError, match="passphrase-protected"):
        _load_private_key(pem, None)


def test_a_wrong_passphrase_is_a_destination_error() -> None:
    pem = _pem(_private_key("ed25519"), passphrase="correct horse")
    with pytest.raises(BackupDestinationError, match="could not parse private key"):
        _load_private_key(pem, "battery staple")


def test_a_pasted_key_with_surrounding_whitespace_is_loaded() -> None:
    key = _private_key("ed25519")

    loaded = _load_private_key("\n   \n" + _pem(key) + "\n\n", None)

    assert f"{loaded.get_name()} {loaded.get_base64()}" == _public_line(key)


async def test_test_connection_with_a_dsa_key_reports_a_failure_instead_of_raising() -> None:
    config = _config(
        _closed_port(),
        private_key=_dsa_openssh_pem(),
        host_key_check="insecure_skip",
    )

    outcome = await ScpDestination().test_connection(config=config)

    assert outcome["ok"] is False
    assert "DSA is not supported" in outcome["error"], outcome


async def test_test_connection_with_a_private_key_reports_a_failure_instead_of_raising() -> None:
    # Nothing listens on the port: the key loads, the connect is refused, and
    # Test connection says so. It used to raise AttributeError (a 500).
    config = _config(
        _closed_port(),
        private_key=_pem(_private_key("ed25519")),
        host_key_check="insecure_skip",
    )

    outcome = await ScpDestination().test_connection(config=config)

    assert outcome["ok"] is False
    assert outcome["error"].startswith("SSH connect failed"), outcome


# ── a real handshake checks the pinned key ──────────────────────────────


@pytest.mark.parametrize("kind", KINDS)
def test_a_pinned_host_key_lets_the_driver_sign_in(kind: str) -> None:
    host_key, public = _host_key(kind)
    with _ssh_server(host_key) as port:
        config = _config(
            port,
            password=_PASSWORD,
            host_key_check="known_hosts",
            known_hosts=f"[127.0.0.1]:{port} {public}\n",
        )

        client = ScpDestination()._connect(config)
        client.close()


def test_a_server_whose_key_differs_from_the_pinned_one_is_refused_as_a_mismatch() -> None:
    host_key, _ = _host_key("ed25519")
    _, other_public = _host_key("ed25519")
    with _ssh_server(host_key) as port:
        config = _config(
            port,
            password=_PASSWORD,
            host_key_check="known_hosts",
            known_hosts=f"[127.0.0.1]:{port} {other_public}\n",
        )

        with pytest.raises(BackupDestinationError, match="does not match"):
            ScpDestination()._connect(config)


def test_a_server_with_no_pinned_key_is_refused() -> None:
    host_key, public = _host_key("ed25519")
    with _ssh_server(host_key) as port:
        config = _config(
            port,
            password=_PASSWORD,
            host_key_check="known_hosts",
            known_hosts=f"[sftp.example]:{port} {public}\n",
        )

        with pytest.raises(BackupDestinationError, match="not found in known_hosts"):
            ScpDestination()._connect(config)


def test_a_private_key_signs_in_to_a_server_whose_key_is_pinned() -> None:
    host_key, public = _host_key("ed25519")
    user_key = _private_key("ed25519")
    user_pem = _pem(user_key)
    authorized = paramiko.Ed25519Key.from_private_key(io.StringIO(user_pem))
    with _ssh_server(host_key, user_key=authorized) as port:
        config = _config(
            port,
            private_key=user_pem,
            host_key_check="known_hosts",
            known_hosts=f"[127.0.0.1]:{port} {public}\n",
        )

        client = ScpDestination()._connect(config)
        client.close()
