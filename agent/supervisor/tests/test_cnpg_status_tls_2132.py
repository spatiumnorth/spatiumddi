"""#2132 / #2765 — the primary's slot state is read with its TLS verified
against the cluster CA.

The re-clone decision rests on the primary's ``pg_replication_slots``, read
off CNPG's instance-manager status endpoint (``https://<pod IP>:8000/pg/status``).
That endpoint presents the cluster's server certificate: signed by the cluster
CA, with the cluster's service names (``<cluster>-rw`` and friends) as SANs and
never the pod IP. So the read connects to the IP and checks the certificate
against the CA under the name ``<cluster>-rw``. The CA's public certificate
comes from the ConfigMap the control chart publishes it into, never from the
CA secret (which also holds the private key).

These tests run a real TLS server on 127.0.0.1 and drive the real reader: a
certificate from the cluster CA under the right name is read; a self-signed
one, one from another CA, one under another name, and a missing CA ConfigMap
all leave the slot state unknown, and an unknown slot state re-clones nothing.
"""

from __future__ import annotations

import datetime
import http.server
import json
import ssl
import threading
from contextlib import contextmanager
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from spatium_supervisor import heartbeat, k8s_api

from .test_postgres_reclone_stuck_2132 import (
    CA_CM_PATH,
    CASE4,
    CLUSTER,
    HEALTHY,
    P1,
    P2,
    P3,
    _Kube,
    _Log,
    _pod,
)

RW = f"{CLUSTER}-rw"


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_key, subject, issuer_key, issuer, *, ca: bool, sans=()):
    now = datetime.datetime.now(datetime.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        b = b.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if sans:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False
        )
    return b.sign(issuer_key, hashes.SHA256())


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class _CA:
    def __init__(self, cn: str) -> None:
        self.key = _key()
        self.name = _name(cn)
        self.cert = _cert(self.key, self.name, self.key, self.name, ca=True)
        self.pem = _pem(self.cert)

    def leaf(self, sans) -> tuple:
        key = _key()
        return key, _cert(key, _name(sans[0]), self.key, self.name, ca=False, sans=sans)


CLUSTER_CA = _CA(CLUSTER)
OTHER_CA = _CA("some-other-ca")


def _status_doc(slots: dict[str, str]) -> dict:
    return {
        "isPrimary": True,
        "replicationSlotsInfo": [
            {"slotName": "_cnpg_" + i.replace("-", "_"), "walStatus": w} for i, w in slots.items()
        ],
    }


@contextmanager
def _status_server(tmp_path: Path, key, cert, doc: dict):
    """A TLS endpoint on 127.0.0.1 answering ``doc`` at /pg/status."""
    cert_file = tmp_path / "tls.crt"
    key_file = tmp_path / "tls.key"
    cert_file.write_text(_pem(cert))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    body = json.dumps(doc).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/pg/status":
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):  # quiet
            return

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_file), str(key_file))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


class _TlsKube(_Kube):
    """The reclone harness with the primary at 127.0.0.1, the real status
    reader, and the CA ConfigMap scripted (``ca_pem=None``: absent)."""

    def __init__(self, *, ca_pem: str | None, ca_status: int = 200, **kw) -> None:
        primary = _pod(P1)
        primary["status"]["podIP"] = "127.0.0.1"
        super().__init__(pods=[primary, _pod(P2), _pod(P3)], **kw)
        self.ca_pem = ca_pem
        self.ca_status = ca_status

    def __call__(self, method, path, body=None, content_type=None, timeout=None):
        if method == "GET" and path == CA_CM_PATH:
            self.gets.append(path)
            if self.ca_pem is None:
                return self.ca_status, b"{}"
            return 200, json.dumps({"data": {"ca.crt": self.ca_pem}}).encode()
        return super().__call__(method, path, body, content_type, timeout)


def _drive(monkeypatch, kube: _TlsKube, port: int, *, until: int = 900):
    """Ticks of the real reclone (real ``_cnpg_instance_status``) until due."""
    monkeypatch.setattr(k8s_api, "_request", kube)
    monkeypatch.setattr(k8s_api, "_CNPG_STATUS_PORT", port)
    tracker: dict = {}
    out = None
    for now in range(0, until, 30):
        out = k8s_api.reclone_stuck_postgres_instances(tracker, now=now, stuck_after_s=600)
    return out


def test_a_certificate_from_the_cluster_ca_is_read(tmp_path, monkeypatch):
    key, cert = CLUSTER_CA.leaf([RW, f"{RW}.spatium.svc"])
    with _status_server(tmp_path, key, cert, _status_doc({P3: "lost"})) as port:
        monkeypatch.setattr(k8s_api, "_CNPG_STATUS_PORT", port)
        doc, why = k8s_api._cnpg_instance_status(
            "127.0.0.1", ca_pem=CLUSTER_CA.pem, server_hostname=RW
        )
        assert why == "" and doc and doc["isPrimary"] is True
        # End to end: the lost slot is read, so the stuck standby is re-cloned.
        kube = _TlsKube(ca_pem=CLUSTER_CA.pem, logs={P2: HEALTHY, P3: CASE4})
        out = _drive(monkeypatch, kube, port)
    assert out.slot_state_read and out.slot_state_error == ""
    assert out.stuck[P3]["slot"] == "lost"
    assert kube.marked == [P3]


def _assert_held_unknown(out, kube, needle: str):
    assert kube.patches == [], "nothing may be re-cloned while the slot state is unknown"
    assert out.marked == []
    assert out.stuck[P3]["slot"] == "unknown"
    assert P3 in out.held and "could not be read" in out.held[P3]
    assert not out.slot_state_read
    assert needle in out.slot_state_error, out.slot_state_error


def test_a_self_signed_certificate_is_refused(tmp_path, monkeypatch):
    key = _key()
    cert = _cert(key, _name(RW), key, _name(RW), ca=False, sans=[RW])
    with _status_server(tmp_path, key, cert, _status_doc({P3: "lost"})) as port:
        kube = _TlsKube(ca_pem=CLUSTER_CA.pem, logs={P2: HEALTHY, P3: CASE4})
        out = _drive(monkeypatch, kube, port)
    _assert_held_unknown(out, kube, "did not verify against the cluster CA")


def test_a_certificate_from_another_ca_is_refused(tmp_path, monkeypatch):
    key, cert = OTHER_CA.leaf([RW])
    with _status_server(tmp_path, key, cert, _status_doc({P3: "lost"})) as port:
        kube = _TlsKube(ca_pem=CLUSTER_CA.pem, logs={P2: HEALTHY, P3: CASE4})
        out = _drive(monkeypatch, kube, port)
    _assert_held_unknown(out, kube, "did not verify against the cluster CA")


def test_a_certificate_for_another_name_is_refused(tmp_path, monkeypatch):
    # Signed by the right CA, but not for this cluster's services.
    key, cert = CLUSTER_CA.leaf(["some-other-cluster-rw"])
    with _status_server(tmp_path, key, cert, _status_doc({P3: "lost"})) as port:
        monkeypatch.setattr(k8s_api, "_CNPG_STATUS_PORT", port)
        doc, why = k8s_api._cnpg_instance_status(
            "127.0.0.1", ca_pem=CLUSTER_CA.pem, server_hostname=RW
        )
        assert doc is None and "did not verify" in why
        kube = _TlsKube(ca_pem=CLUSTER_CA.pem, logs={P2: HEALTHY, P3: CASE4})
        out = _drive(monkeypatch, kube, port)
    _assert_held_unknown(out, kube, "did not verify against the cluster CA")


def test_a_missing_ca_certificate_is_unknown(tmp_path, monkeypatch):
    key, cert = CLUSTER_CA.leaf([RW])
    with _status_server(tmp_path, key, cert, _status_doc({P3: "lost"})) as port:
        # The ConfigMap is not there (publisher not run yet) ...
        kube = _TlsKube(ca_pem=None, ca_status=404, logs={P2: HEALTHY, P3: CASE4})
        out = _drive(monkeypatch, kube, port)
        _assert_held_unknown(out, kube, "does not exist")
        # ... or is there without the key, or with something that is not a
        # certificate: the same.
        for bad in ("", "not a certificate"):
            kube = _TlsKube(ca_pem=bad, logs={P2: HEALTHY, P3: CASE4})
            out = _drive(monkeypatch, kube, port)
            _assert_held_unknown(out, kube, "carries no ca.crt certificate")
        # ... or forbidden.
        kube = _TlsKube(ca_pem=None, ca_status=403, logs={P2: HEALTHY, P3: CASE4})
        out = _drive(monkeypatch, kube, port)
        _assert_held_unknown(out, kube, "kubeapi status 403")
    # The CA secret is never asked for: it holds the private key.
    assert not any("/secrets/" in g for g in kube.gets)


def test_heartbeat_logs_each_unknown_reason_once_then_the_verified_read(tmp_path, monkeypatch):
    monkeypatch.setattr(heartbeat, "_stuck_postgres", {})
    monkeypatch.setattr(heartbeat, "_stuck_postgres_reported", {})
    monkeypatch.setattr(heartbeat, "_stuck_postgres_held", {})
    monkeypatch.setattr(heartbeat, "_slot_state_logged", set())
    log = _Log()
    key, cert = OTHER_CA.leaf([RW])
    with _status_server(tmp_path, key, cert, _status_doc({P3: "reserved"})) as port:
        kube = _TlsKube(ca_pem=CLUSTER_CA.pem, logs={P2: HEALTHY, P3: CASE4})
        monkeypatch.setattr(k8s_api, "_request", kube)
        monkeypatch.setattr(k8s_api, "_CNPG_STATUS_PORT", port)
        for now in range(0, 900, 30):
            heartbeat._reclone_stuck_postgres(log, now=now)
    unknown = [e for e in log.events if e[1].endswith("postgres_slot_state_unknown")]
    assert len(unknown) == 1 and unknown[0][0] == "warning"
    assert "did not verify" in unknown[0][2]["reason"]
    key, cert = CLUSTER_CA.leaf([RW])
    with _status_server(tmp_path, key, cert, _status_doc({P3: "reserved"})) as port:
        monkeypatch.setattr(k8s_api, "_CNPG_STATUS_PORT", port)
        for now in range(900, 1500, 30):
            heartbeat._reclone_stuck_postgres(log, now=now)
    read = [e for e in log.events if e[1].endswith("postgres_slot_state_read")]
    assert len(read) == 1 and read[0][2]["tls"] == "verified against the cluster CA"
    assert kube.patches == []  # reserved: held, never re-cloned
