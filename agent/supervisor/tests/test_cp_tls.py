"""The supervisor verifies the control plane's certificate (#1219).

Every supervisor -> control plane request used to run with TLS verification
off (the appliance chart set ``SPATIUM_INSECURE_SKIP_TLS_VERIFY=1``), and the
heartbeat response carries the agent keys and the slot image URL plus the
sha256 that is its only integrity check. These drive ``cp_tls`` against REAL
local TLS servers, because the properties that matter are OpenSSL's: that
the check happens in the handshake, that a CA-issued leaf can be the trust
anchor, and that the hostname does not have to match.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import socket
import ssl
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from spatium_supervisor import cp_tls

# ── certificates ─────────────────────────────────────────────────────────────


@dataclass
class Cert:
    pem: str
    key_pem: str

    @property
    def sha256(self) -> str:
        return cp_tls.cert_sha256(self.pem)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key_pem(key: Any) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _leaf(cn: str, issuer: tuple[x509.Name, Any] | None = None) -> Cert:
    """A server certificate for ``cn``: self-signed, or issued by ``issuer``."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    iss_name, iss_key = issuer if issuer else (_name(cn), key)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(iss_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(iss_key, hashes.SHA256())
    )
    return Cert(cert.public_bytes(serialization.Encoding.PEM).decode(), _key_pem(key))


@dataclass
class CA:
    """A stand-in for the appliance CA: RSA, like the real one."""

    name: x509.Name
    key: rsa.RSAPrivateKey
    pem: str

    def sign_list(self, fingerprints: list[str], issued_at: datetime | None = None) -> dict[str, str]:
        payload = json.dumps(
            {
                "version": 1,
                "certs_sha256": fingerprints,
                "issued_at": (issued_at or datetime.now(UTC)).isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        sig = self.key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return {
            "payload": base64.b64encode(payload).decode(),
            "signature": base64.b64encode(sig).decode(),
            "algorithm": "rsa-pss-sha256",
            "ca_cert_sha256": hashlib.sha256(b"x").hexdigest(),
        }


def _ca(cn: str = "Test Appliance CA") -> CA:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return CA(_name(cn), key, cert.public_bytes(serialization.Encoding.PEM).decode())


# ── a control plane ──────────────────────────────────────────────────────────


class SwappableServer:
    """An HTTPS control plane whose certificate and signed list a test can
    swap. Each accepted connection is wrapped with the CURRENT certificate,
    so a rotation needs no rebind."""

    def __init__(self, tmp: Path, cert: Cert) -> None:
        self.tmp = tmp
        self.pin_set: dict[str, str] | None = None
        self.requests: list[str] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802
                outer.requests.append(self.path)
                if self.path == cp_tls.PIN_SET_PATH and outer.pin_set is not None:
                    body = json.dumps(outer.pin_set).encode()
                else:
                    body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET  # noqa: N815

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        # Tests abort connections on purpose (a refused handshake is the
        # point); the server's default handler would print each one.
        self.httpd.handle_error = lambda *a: None  # type: ignore[method-assign]
        raw_get_request = self.httpd.get_request

        def get_request() -> tuple[Any, Any]:
            sock, addr = raw_get_request()
            return outer._ctx.wrap_socket(sock, server_side=True), addr

        self.httpd.get_request = get_request  # type: ignore[method-assign]
        self.use(cert)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def use(self, cert: Cert) -> None:
        """Present ``cert`` from the next handshake on."""
        certfile = self.tmp / f"srv-{cert.sha256[:12]}.pem"
        keyfile = self.tmp / f"srv-{cert.sha256[:12]}.key"
        certfile.write_text(cert.pem)
        keyfile.write_text(cert.key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        self._ctx = ctx

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.httpd.server_address[1]}"

    def current_pem(self) -> str:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", self.httpd.server_address[1])) as raw:
            with ctx.wrap_socket(raw) as tls:
                return ssl.DER_cert_to_PEM_cert(tls.getpeercert(binary_form=True))

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server(tmp_path: Path) -> Iterator[SwappableServer]:
    srv = SwappableServer(tmp_path, _leaf("control-plane.example"))
    yield srv
    srv.close()


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPATIUM_INSECURE_SKIP_TLS_VERIFY", raising=False)
    monkeypatch.setattr(cp_tls, "_redirects", {})
    monkeypatch.setattr(cp_tls, "_vouch_checked", False)


def _state(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir()
    return state


def _approve(state: Path, ca: CA) -> None:
    """What the first heartbeat after approval leaves on disk."""
    (state / "tls").mkdir(parents=True, exist_ok=True)
    (state / "tls" / "ca-chain.pem").write_text(ca.pem)


# ── pin on first contact, verify in the handshake ────────────────────────────


def test_first_contact_pins_the_presented_certificate(server, tmp_path: Path) -> None:
    state = _state(tmp_path)
    with cp_tls.client(state, server.url) as c:
        assert c.get(server.url + "/x").status_code == 200
    pins = cp_tls.load_pins(state)
    assert pins is not None
    assert cp_tls.cert_sha256(pins) == cp_tls.cert_sha256(server.current_pem())


def test_a_different_certificate_is_refused_in_the_handshake(server, tmp_path: Path) -> None:
    """The whole point: nothing is sent to a server that does not hold the
    pinned key, so no session token reaches an interceptor."""
    state = _state(tmp_path)
    with cp_tls.client(state, server.url) as c:
        c.get(server.url + "/x")
    server.use(_leaf("attacker.example"))
    server.requests.clear()
    with cp_tls.client(state, server.url) as c, pytest.raises(httpx.ConnectError) as exc:
        c.post(server.url + "/api/v1/appliance/supervisor/heartbeat", json={"session_token": "s"})
    assert cp_tls.is_verification_failure(exc.value)
    assert server.requests == [], "the request never reached the server"


def test_the_hostname_does_not_have_to_match(server, tmp_path: Path) -> None:
    """The certificate names control-plane.example; the supervisor dials
    127.0.0.1, as an operator who typed an IP does."""
    state = _state(tmp_path)
    with cp_tls.client(state, server.url) as c:
        c.get(server.url + "/x")
    with cp_tls.client(state, server.url) as c:
        assert c.get(server.url + "/x").status_code == 200


def test_a_ca_issued_leaf_can_be_pinned(tmp_path: Path) -> None:
    """An uploaded or ACME certificate is not self-signed. Pinning the leaf
    has to work anyway, which needs VERIFY_X509_PARTIAL_CHAIN."""
    issuer = _ca("Some Public-ish CA")
    leaf = _leaf("control-plane.example", (issuer.name, issuer.key))
    srv = SwappableServer(tmp_path, leaf)
    try:
        state = _state(tmp_path)
        with cp_tls.client(state, srv.url) as c:
            c.get(srv.url + "/x")
        with cp_tls.client(state, srv.url) as c:
            assert c.get(srv.url + "/x").status_code == 200
    finally:
        srv.close()


def test_the_skip_flag_still_disables_verification(server, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPATIUM_INSECURE_SKIP_TLS_VERIFY", "1")
    state = _state(tmp_path)
    with cp_tls.client(state, server.url) as c:
        assert c.get(server.url + "/x").status_code == 200
    assert cp_tls.load_pins(state) is None


def test_a_proxy_loop_does_not_take_the_pin(server, tmp_path: Path) -> None:
    """Only registration pins. Without a pin a proxy loop gets system-CA
    verification, which a self-signed control plane fails: closed, not open."""
    state = _state(tmp_path)
    with cp_tls.client(state, server.url, first_contact=False) as c, pytest.raises(httpx.ConnectError):
        c.get(server.url + "/x")
    assert cp_tls.load_pins(state) is None


def test_an_in_cluster_http_url_has_no_certificate(tmp_path: Path) -> None:
    assert cp_tls.tls_url("http://spatium-control-spatiumddi-api.spatium.svc.cluster.local:8000") is None


def test_an_http_url_is_sent_to_its_https_target_not_over_http(
    server, tmp_path: Path
) -> None:
    """The installer allows http:// for labs, and the frontend redirects it.
    The request body (a pairing code, a session token) must never cross the
    wire in cleartext first, so the http origin is only probed with a bare GET
    to learn the target, and every real request goes straight to https."""
    seen: list[str] = []

    class Redirect(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def _redirect(self) -> None:
            seen.append(f"{self.command} {self.path}")
            self.send_response(301)
            self.send_header("Location", server.url + self.path)
            self.end_headers()

        do_GET = do_POST = _redirect  # noqa: N815

    plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{plain.server_address[1]}"
        assert cp_tls.tls_url(url) == server.url + "/"
        state = _state(tmp_path)
        server.requests.clear()
        with cp_tls.client(state, url) as c:
            resp = c.post(
                url + "/api/v1/appliance/supervisor/heartbeat", json={"session_token": "s"}
            )
        assert resp.status_code == 200
        assert server.requests == ["/api/v1/appliance/supervisor/heartbeat"], "POST, over https"
        assert seen == ["GET /"], "only the bare probe ever touched http"
        assert cp_tls.load_pins(state) is not None
    finally:
        plain.shutdown()
        plain.server_close()


# ── rotation through the appliance CA ────────────────────────────────────────


def _pinned(server: SwappableServer, tmp_path: Path) -> Path:
    state = _state(tmp_path)
    with cp_tls.client(state, server.url) as c:
        c.get(server.url + "/x")
    return state


def test_a_rotation_the_ca_vouches_for_is_adopted(server, tmp_path: Path) -> None:
    state = _pinned(server, tmp_path)
    ca = _ca()
    _approve(state, ca)
    new = _leaf("control-plane.example")
    server.use(new)
    server.pin_set = ca.sign_list([new.sha256])

    assert cp_tls.try_repin(state, server.url) is True
    assert cp_tls.cert_sha256(cp_tls.load_pins(state)) == new.sha256
    with cp_tls.client(state, server.url) as c:
        assert c.get(server.url + "/x").status_code == 200


def test_a_certificate_the_ca_does_not_vouch_for_is_refused(server, tmp_path: Path) -> None:
    """An interceptor relaying the real signed list still is not on it."""
    state = _pinned(server, tmp_path)
    before = cp_tls.load_pins(state)
    ca = _ca()
    _approve(state, ca)
    real = _leaf("control-plane.example")
    server.use(_leaf("attacker.example"))
    server.pin_set = ca.sign_list([real.sha256])

    assert cp_tls.try_repin(state, server.url) is False
    assert cp_tls.load_pins(state) == before


def test_a_list_signed_by_another_ca_is_refused(server, tmp_path: Path) -> None:
    """An interceptor can sign a list naming its own certificate; it cannot
    sign one with the appliance CA's key."""
    state = _pinned(server, tmp_path)
    before = cp_tls.load_pins(state)
    _approve(state, _ca())
    attacker = _leaf("attacker.example")
    server.use(attacker)
    server.pin_set = _ca("Attacker CA").sign_list([attacker.sha256])

    assert cp_tls.try_repin(state, server.url) is False
    assert cp_tls.load_pins(state) == before


def test_a_stale_list_is_refused(server, tmp_path: Path) -> None:
    """A list captured before a rotation cannot vouch for a retired
    certificate forever."""
    state = _pinned(server, tmp_path)
    ca = _ca()
    _approve(state, ca)
    new = _leaf("control-plane.example")
    server.use(new)
    server.pin_set = ca.sign_list([new.sha256], issued_at=datetime.now(UTC) - timedelta(days=3))

    assert cp_tls.try_repin(state, server.url) is False


def test_before_approval_a_new_certificate_is_pinned_again(server, tmp_path: Path) -> None:
    """No CA yet, so there is nothing to ask; nothing withheld from an
    unapproved node has flowed either."""
    state = _pinned(server, tmp_path)
    new = _leaf("control-plane.example")
    server.use(new)
    assert cp_tls.try_repin(state, server.url) is True
    assert cp_tls.cert_sha256(cp_tls.load_pins(state)) == new.sha256


def test_the_same_certificate_is_not_a_rotation(server, tmp_path: Path) -> None:
    state = _pinned(server, tmp_path)
    _approve(state, _ca())
    assert cp_tls.try_repin(state, server.url) is False


# ── the first-contact pin, checked once approved ─────────────────────────────


def test_a_vouched_first_contact_pin_passes(server, tmp_path: Path) -> None:
    state = _pinned(server, tmp_path)
    ca = _ca()
    _approve(state, ca)
    server.pin_set = ca.sign_list([cp_tls.cert_sha256(cp_tls.load_pins(state))])
    with _capture() as logs:
        cp_tls.check_pin_vouched_once(state, server.url)
    assert [e["event"] for e in logs] == ["supervisor.tls.pin_vouched"]


def test_an_intercepted_first_contact_is_reported(server, tmp_path: Path) -> None:
    """Pinned at pairing through an interceptor: the CA's list names the
    real certificate, not the one this supervisor trusted."""
    state = _pinned(server, tmp_path)
    ca = _ca()
    _approve(state, ca)
    server.pin_set = ca.sign_list([_leaf("control-plane.example").sha256])
    with _capture() as logs:
        cp_tls.check_pin_vouched_once(state, server.url)
    assert [e["event"] for e in logs] == ["supervisor.tls.pin_not_vouched"]
    assert logs[0]["log_level"] == "error"


# ── the signed list, on its own ──────────────────────────────────────────────


def test_verify_pin_set_rejects_a_tampered_payload() -> None:
    ca = _ca()
    signed = ca.sign_list(["aa" * 32])
    payload = json.loads(base64.b64decode(signed["payload"]))
    payload["certs_sha256"].append("bb" * 32)
    signed["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
    with pytest.raises(cp_tls.PinSetError, match="does not verify"):
        cp_tls.verify_pin_set(signed, ca.pem)


def test_verify_pin_set_rejects_another_algorithm() -> None:
    ca = _ca()
    signed = ca.sign_list(["aa" * 32])
    signed["algorithm"] = "none"
    with pytest.raises(cp_tls.PinSetError, match="algorithm"):
        cp_tls.verify_pin_set(signed, ca.pem)


def test_verify_pin_set_accepts_a_good_list() -> None:
    ca = _ca()
    assert cp_tls.verify_pin_set(ca.sign_list(["AA" * 32]), ca.pem) == {"aa" * 32}


def test_display_fingerprint_matches_the_control_planes_format() -> None:
    """``AB:CD:...``, as Appliance -> TLS shows it, so an operator can compare."""
    assert cp_tls.display_fingerprint("abcd12") == "AB:CD:12"


# ── helpers ──────────────────────────────────────────────────────────────────


def _capture():  # type: ignore[no-untyped-def]
    from structlog.testing import capture_logs

    return capture_logs()

