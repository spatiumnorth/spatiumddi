"""The agent verifies the control plane against a pinned certificate (#1281).

On an off-cluster appliance the role pods used to reach the control plane with
SPATIUM_INSECURE_SKIP_TLS_VERIFY=1, sending the agent key out and taking their
configuration back over a connection anyone on the path could terminate. The
chart now points TLS_PINNED_CERTS_PATH at the supervisor's pin instead.

TLS_CA_PATH could not stand in for it: it is a CA bundle checked with hostname
verification, so a pinned leaf that a CA issued (an uploaded or ACME
certificate) fails there, and an operator may have typed an IP. These tests run
real handshakes against a local server rather than asserting on the context's
flags, because a context that merely LOOKS right and trusts the system store,
or checks the hostname, passes every flag assertion and fails in the field.
"""

from __future__ import annotations

import dataclasses
import datetime
import inspect
import socket
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import spatium_dhcp_agent.config as config_module
from spatium_dhcp_agent.config import AgentConfig, pinned_context


@pytest.fixture
def base_cfg(agent_cfg: AgentConfig) -> AgentConfig:
    return agent_cfg


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _issue(
    cn: str,
    *,
    issuer: tuple[ec.EllipticCurvePrivateKey, x509.Certificate] | None = None,
    ca: bool = False,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    signer_key, issuer_name = (issuer[0], issuer[1].subject) if issuer else (key, name)
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        # Names the certificate does NOT carry for the address the test dials,
        # so a context that checked the hostname would refuse it.
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("cp.example")]), critical=False
        )
    return key, builder.sign(signer_key, hashes.SHA256())


@pytest.fixture(scope="module")
def ca_issued_leaf(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, str]:
    """A leaf a CA issued, served by the test server: (cert, key, leaf PEM)."""
    ca = _issue("test ca", ca=True)
    key, leaf = _issue("cp.example", issuer=ca)
    d = tmp_path_factory.mktemp("server")
    cert_path, key_path = d / "cert.pem", d / "key.pem"
    cert_path.write_text(_pem(leaf) + _pem(ca[1]), encoding="ascii")
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, _pem(leaf)


@pytest.fixture
def server(ca_issued_leaf: tuple[Path, Path, str]) -> Iterator[int]:
    """A TLS server on 127.0.0.1 that completes (or fails) one handshake per
    connection. Yields its port."""
    cert_path, key_path, _ = ca_issued_leaf
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert_path, key_path)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with sctx.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass  # the client refusing us is a result the test asserts on

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    stop.set()
    listener.close()
    t.join(timeout=2)


def _handshake(ctx: ssl.SSLContext, port: int) -> None:
    with (
        socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
        ctx.wrap_socket(raw, server_hostname=None) as tls,
    ):
        tls.sendall(b"x")


def test_a_pinned_ca_issued_leaf_is_trusted_at_an_ip(
    tmp_path: Path, server: int, ca_issued_leaf: tuple[Path, Path, str]
) -> None:
    """The leaf alone is the anchor (partial chain), and the hostname it names
    is not the address dialled: both must pass."""
    pin = tmp_path / "control-plane.pem"
    pin.write_text(ca_issued_leaf[2], encoding="ascii")
    _handshake(pinned_context(str(pin)), server)


def test_a_different_certificate_is_refused(tmp_path: Path, server: int) -> None:
    pin = tmp_path / "control-plane.pem"
    pin.write_text(_pem(_issue("someone else")[1]), encoding="ascii")
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(pinned_context(str(pin)), server)


@pytest.mark.parametrize("content", [None, "", "not a certificate\n"])
def test_no_pin_fails_closed(tmp_path: Path, server: int, content: str | None) -> None:
    """Before the supervisor has pinned: every handshake fails, and building
    the context does not raise (a raise would kill the client's thread)."""
    pin = tmp_path / "control-plane.pem"
    if content is not None:
        pin.write_text(content, encoding="ascii")
    ctx = pinned_context(str(pin))
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(ctx, server)


def test_a_repin_is_picked_up_without_a_restart(
    tmp_path: Path, server: int, ca_issued_leaf: tuple[Path, Path, str]
) -> None:
    """The file is read per client build, so the next client after the
    supervisor re-pins verifies against the new certificate."""
    pin = tmp_path / "control-plane.pem"
    pin.write_text(_pem(_issue("the old certificate")[1]), encoding="ascii")
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(pinned_context(str(pin)), server)
    pin.write_text(ca_issued_leaf[2], encoding="ascii")
    _handshake(pinned_context(str(pin)), server)


def test_the_system_store_is_not_trusted(tmp_path: Path) -> None:
    """Only the pin: a context that also loaded the system CAs would accept
    any publicly trusted certificate for any host."""
    pin = tmp_path / "control-plane.pem"
    pin.write_text(_pem(_issue("pinned")[1]), encoding="ascii")
    assert pinned_context(str(pin)).cert_store_stats()["x509"] == 1


@pytest.mark.parametrize(
    ("ca", "skip"), [(None, False), ("/ca.crt", False), (None, True), ("/ca.crt", True)]
)
def test_the_pin_wins_over_the_ca_and_the_skip(
    base_cfg: AgentConfig, tmp_path: Path, ca: str | None, skip: bool
) -> None:
    pin = tmp_path / "control-plane.pem"
    pin.write_text(_pem(_issue("pinned")[1]), encoding="ascii")
    cfg = dataclasses.replace(
        base_cfg,
        control_plane_url="https://10.0.0.1",
        tls_pinned_certs_path=str(pin),
        tls_ca_path=ca,
        insecure_skip_tls_verify=skip,
    )
    verify = cfg.httpx_verify()
    assert isinstance(verify, ssl.SSLContext)
    assert verify.verify_mode == ssl.CERT_REQUIRED
    warning = cfg.tls_warning()
    if ca or skip:
        assert warning is not None and "ignored" in warning
    else:
        assert warning is None


def test_the_env_var_is_read() -> None:
    """``from_env`` is covered through the chart's variable name, since the
    chart and the agent are separate files that must agree on it."""
    assert "tls_pinned_certs_path" in {f.name for f in dataclasses.fields(AgentConfig)}
    assert 'os.environ.get("TLS_PINNED_CERTS_PATH")' in inspect.getsource(config_module)
