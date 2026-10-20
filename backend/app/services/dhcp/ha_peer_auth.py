"""Per-group credential the Kea HA peers of a DHCP server group authenticate with.

Kea's HA hook runs a dedicated HTTP listener (``http-dedicated-listener``,
TCP 8000 by default) that its partner sends heartbeats, lease updates and
lease-sync pages to. The listener answers HA commands — ``lease4-update``,
``lease4-del``, ``dhcp-disable``, ``ha-sync-complete-notify`` … — so only
the group's own peers should be able to talk to it.

**Why a TLS client certificate and not ``basic-auth-user``.** Kea's HA peer
config does accept ``basic-auth-user`` / ``basic-auth-password``, but in the
version we ship (3.0.x) those only make the hook ADD an ``Authorization``
header to the requests it sends. The dedicated listener never checks one:
``CmdResponseCreator::http_auth_config_`` is the hook's server-side auth
config, and the HA hook never sets it (``src/lib/config/cmd_response_creator.h``
says so in as many words). A password would therefore be sent and ignored.
What the listener does enforce is TLS with ``require-client-certs`` — on by
default once ``trust-anchor`` / ``cert-file`` / ``key-file`` are configured
(``ha_config.cc``: the entry for this server builds the SERVER context with
``cert_required = require-client-certs``; every other entry builds a CLIENT
context that always verifies the peer). Kea checks the chain against the
trust anchor and does no hostname matching, so one certificate per group,
shared by its peers, authenticates either side to the other.

The credential is generated here, per group, as a throwaway CA plus one leaf
signed by it. The CA's private key is discarded the moment the leaf is
signed, so nothing can mint a second certificate the group would accept;
rotating means generating a whole new set. Only the bundle carries it to the
agents. It is stored Fernet-encrypted, never returned by the API (a boolean
says whether one exists), and never logged or audited.

**Rollout gate.** Kea cannot run its listener with optional TLS: a listener
with TLS refuses a plaintext peer and a plaintext listener refuses a TLS one.
So the credential is rendered only once EVERY Kea member of the group
advertises :data:`HA_PEER_TLS_CAPABILITY` on its heartbeat. While any member
runs an agent that predates it, the group keeps the previous plaintext
config, and the moment the last one reports the capability every member's
bundle changes together. See ``docs/drivers/DHCP_DRIVERS.md``.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import select

from app.core.crypto import decrypt_dict, encrypt_dict
from app.models.dhcp import DHCPServer, DHCPServerGroup

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

log = structlog.get_logger(__name__)

# Advertised by an agent that renders the credential into its Kea HA hook.
HA_PEER_TLS_CAPABILITY = "ha_peer_tls"

# RFC 5280 §4.1.2.5: 99991231235959Z means "no well-defined expiration".
# An expired HA certificate would stop the pair talking with no operator
# action having caused it; replacement is an explicit rotation instead.
_NOT_AFTER = _dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=_dt.UTC)

_CREDENTIAL_KEYS = ("ca_pem", "cert_pem", "key_pem")


def generate_credential() -> dict[str, str]:
    """A fresh ``{ca_pem, cert_pem, key_pem}`` set for one group."""
    now = _dt.datetime.now(_dt.UTC) - _dt.timedelta(days=1)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SpatiumDDI Kea HA group CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SpatiumDDI Kea HA peer")])
        )
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Each peer is the TLS server on its own listener and the TLS client
        # towards its partner, with the same certificate.
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return {
        "ca_pem": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "cert_pem": leaf_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "key_pem": leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    }


def encrypted_credential() -> bytes:
    """A freshly generated credential, Fernet-encrypted for the column."""
    return encrypt_dict(generate_credential())


def rotate_credential(group: DHCPServerGroup) -> None:
    """Replace the group's credential. Mutates the row; the caller commits."""
    group.ha_peer_credential_encrypted = encrypted_credential()


def group_credential(group: DHCPServerGroup) -> dict[str, str] | None:
    """The group's decrypted credential, or None if it has none / it is unreadable."""
    return _decode_credential(group.ha_peer_credential_encrypted, group.id)


def _decode_credential(token: bytes | None, group_id: object) -> dict[str, str] | None:
    if not token:
        return None
    try:
        data: Any = decrypt_dict(bytes(token))
    except ValueError:
        # Encrypted under a key this install does not hold (a restore whose
        # rewrap failed). Never log the value — only that it is unusable.
        log.warning("dhcp_ha_peer_credential_unreadable", group_id=str(group_id))
        return None
    if not isinstance(data, dict) or not all(
        isinstance(data.get(k), str) and data.get(k) for k in _CREDENTIAL_KEYS
    ):
        log.warning("dhcp_ha_peer_credential_malformed", group_id=str(group_id))
        return None
    return {k: data[k] for k in _CREDENTIAL_KEYS}


def _caps_support_peer_tls(caps: Any) -> bool:
    return isinstance(caps, list) and HA_PEER_TLS_CAPABILITY in caps


def server_supports_peer_tls(server: DHCPServer) -> bool:
    return _caps_support_peer_tls(server.agent_capabilities)


def peer_auth_ready(group: DHCPServerGroup, kea_peers: Iterable[DHCPServer]) -> bool:
    """Whether the group's HA peers can be switched to the credential.

    True only when the group holds a usable credential AND every Kea member
    has said its agent renders one. A member that has never reported (NULL)
    counts as not supporting it.
    """
    peers = list(kea_peers)
    if not peers or not all(server_supports_peer_tls(s) for s in peers):
        return False
    return bool(group.ha_peer_credential_encrypted)


async def current_peer_credential(
    db: AsyncSession, group: DHCPServerGroup, kea_peers: Iterable[DHCPServer]
) -> dict[str, str] | None:
    """The credential to render for the group now, or None while the gate is shut.

    Same rule as :func:`peer_auth_ready`, but read from the database rather
    than from the ORM objects passed in. The config long-poll keeps one
    session for its whole wait and re-queries the group on every wake, and a
    query hands back the objects already in the session's identity map
    without overwriting their loaded attributes. So when the LAST member of a
    pair reports the capability, or a superadmin rotates the credential, the
    partner's parked long-poll would keep seeing the old values and only
    switch when its long-poll timed out — the two peers flipping up to a
    long-poll apart instead of together. Column selects are never served from
    the identity map, so these two always see the committed state.
    """
    ids = [s.id for s in kea_peers]
    if not ids:
        return None
    rows = (
        await db.execute(
            select(DHCPServer.id, DHCPServer.agent_capabilities).where(DHCPServer.id.in_(ids))
        )
    ).all()
    caps = {row.id: row.agent_capabilities for row in rows}
    if not all(_caps_support_peer_tls(caps.get(i)) for i in ids):
        return None
    token = (
        await db.execute(
            select(DHCPServerGroup.ha_peer_credential_encrypted).where(
                DHCPServerGroup.id == group.id
            )
        )
    ).scalar_one_or_none()
    return _decode_credential(token, group.id)


__all__ = [
    "HA_PEER_TLS_CAPABILITY",
    "current_peer_credential",
    "encrypted_credential",
    "generate_credential",
    "group_credential",
    "peer_auth_ready",
    "rotate_credential",
    "server_supports_peer_tls",
]
