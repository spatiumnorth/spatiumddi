"""Write the HA peer credential where Kea's HA hook reads it.

The control plane ships the group's HA peer credential (CA, peer certificate,
key — PEM) inside ``failover.tls`` once every Kea member of the group
advertises :data:`CAPABILITY`. Kea reads ``trust-anchor`` / ``cert-file`` /
``key-file`` from disk, so the agent writes them to ``<state_dir>/ha-tls``
(mode 0600; the agent and both Kea daemons run as the same user) before it
writes the Kea config that references them, and removes them again when the
bundle stops carrying one.

The PEM bodies are never logged.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# Advertised on register + heartbeat; the control plane renders the
# credential only when every Kea peer in the group sends it.
CAPABILITY = "ha_peer_tls"
# Everything this agent advertises on register + heartbeat.
AGENT_CAPABILITIES: tuple[str, ...] = (CAPABILITY,)

CA_FILE = "ca.pem"
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

_FILES = {"ca_pem": CA_FILE, "cert_pem": CERT_FILE, "key_pem": KEY_FILE}


def credential_from_failover(failover: Any) -> dict[str, str] | None:
    """The ``{ca_pem, cert_pem, key_pem}`` set in a failover block, or None."""
    if not isinstance(failover, dict):
        return None
    tls = failover.get("tls")
    if not isinstance(tls, dict):
        return None
    if not all(isinstance(tls.get(k), str) and tls.get(k) for k in _FILES):
        return None
    return {k: tls[k] for k in _FILES}


def tls_paths(directory: str | Path) -> dict[str, str]:
    """The three paths the rendered HA hook points at."""
    d = Path(directory)
    return {
        "trust-anchor": str(d / CA_FILE),
        "cert-file": str(d / CERT_FILE),
        "key-file": str(d / KEY_FILE),
    }


def _write_private(path: Path, body: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, body.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def materialise(failover: Any, directory: str | Path) -> bool:
    """Write (or clear) the credential files for ``failover``.

    Returns True when a credential was written — i.e. the HA hook must be
    rendered with TLS. When the bundle carries none, any files left by an
    earlier bundle are removed so a stale key does not linger on disk.
    """
    d = Path(directory)
    cred = credential_from_failover(failover)
    if cred is None:
        for name in _FILES.values():
            try:
                (d / name).unlink()
            except FileNotFoundError:
                continue
        return False
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except PermissionError:
        # Volume-mount owner may differ; the files themselves are 0600.
        pass
    for key, name in _FILES.items():
        _write_private(d / name, cred[key])
    return True
