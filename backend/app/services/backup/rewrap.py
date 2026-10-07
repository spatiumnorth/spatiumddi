"""Cross-install secret rewrap for restore (issue #117 Phase 2).

When an operator restores an archive on an install whose
``SECRET_KEY`` differs from the one in ``secrets.enc``, every
Fernet-encrypted column in the database still carries the source
install's ciphertext — readable only with the source key, which
isn't on disk anywhere. Without rewrap, the operator has to
manually copy the recovered ``SECRET_KEY`` into the destination's
``.env`` and restart everything; otherwise integration creds /
auth-provider secrets / TSIG keys / etc. all fail to decrypt.

This module runs after the data-replay phase of restore. It:

1. Builds two ``Fernet`` instances using the same derivation
   logic as :mod:`app.core.crypto` — one from the source install's
   key (recovered from ``secrets.enc``), one from the local
   install's key.
2. Bails early when the keys are identical (same-install
   restore — no rewrap needed).
3. For every (table, column) in :data:`ENCRYPTED_COLUMNS`,
   walks every non-null row, decrypts with the source key,
   re-encrypts with the destination key, UPDATEs the row.
4. Walks every JSONB-embedded Fernet string listed in
   :data:`JSONB_ENCRYPTED_FIELDS` — the ``__enc__:`` fields inside
   ``backup_target.config`` plus the SNMPv3 passphrases, syslog TLS
   CAs, APT GPG keys and private-mirror passwords on
   ``platform_settings``. Those are JSON strings rather than
   ``LargeBinary`` columns, so the column sweep cannot see them.

Idempotency: if a row is already encrypted with the destination
key (rewrap re-run, or a row created post-restore via the API),
``InvalidToken`` from the source-key attempt is swallowed and we
verify against the dest key — already-rewrapped rows count as
``skipped_idempotent``, not failures. Rows that decrypt with
neither key are logged as ``failed`` and left untouched; the
restore still succeeds, the operator gets a count.

The rewrap opens its own asyncpg connection rather than reusing
the SQLAlchemy engine — the restore phase disposes that engine
on purpose (so psql / pg_restore can run unobstructed), and this
runs immediately after that disposal. A short-lived asyncpg
connection avoids reviving the pool prematurely.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import asyncpg
import structlog
from cryptography.fernet import Fernet, InvalidToken

logger = structlog.get_logger(__name__)

# All (table, primary_key_column, encrypted_bytes_column) triples in the
# schema. Sorted alphabetically by table for diffability.
#
# Kept explicit rather than auto-discovered, so that adding a
# Fernet-encrypted column is a deliberate review decision — but
# ``test_rewrap_covers_every_encrypted_column`` asserts this list matches
# the mapped metadata exactly, because "explicit" only works if drift is
# caught. It wasn't: this list covered 21 of 47 columns and named one
# table that does not exist, so a cross-install restore silently left
# every other credential encrypted under the SOURCE key (#781). On an
# appliance that is every restore, since firstboot mints fresh keys.
ENCRYPTED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("acme_client_account", "id", "account_key_encrypted"),
    ("acme_client_account", "id", "eab_hmac_encrypted"),
    ("ai_provider", "id", "api_key_encrypted"),
    ("appliance", "id", "desired_k3s_join_token_encrypted"),
    ("appliance", "id", "k3s_join_token_encrypted"),
    ("appliance", "id", "kubeconfig_encrypted"),
    ("appliance_ca", "id", "key_encrypted"),
    ("appliance_certificate", "id", "key_encrypted"),
    ("audit_forward_target", "id", "auth_header_encrypted"),
    ("audit_forward_target", "id", "smtp_password_encrypted"),
    ("audit_forward_target", "id", "url_encrypted"),
    ("auth_provider", "id", "secrets_encrypted"),
    ("backup_target", "id", "passphrase_encrypted"),
    ("bgp_lg_peer", "id", "md5_password_encrypted"),
    ("cloud_endpoint", "id", "credentials_encrypted"),
    ("dhcp_server", "id", "credentials_encrypted"),
    ("dns_server", "id", "api_key_encrypted"),
    ("dns_server", "id", "credentials_encrypted"),
    ("dns_server_group", "id", "tsig_key_secret_encrypted"),
    ("dns_tsig_key", "id", "secret_encrypted"),
    ("docker_host", "id", "client_key_encrypted"),
    ("event_subscription", "id", "secret_encrypted"),
    ("firewall_feed", "id", "token_encrypted"),
    ("fortinet_firewall", "id", "api_token_encrypted"),
    ("influxdb_target", "id", "password_encrypted"),
    ("influxdb_target", "id", "token_encrypted"),
    ("kubernetes_cluster", "id", "token_encrypted"),
    ("meraki_org", "id", "api_key_encrypted"),
    ("meraki_org", "id", "block_sync_api_key_encrypted"),
    ("netbird_instance", "id", "api_key_encrypted"),
    ("network_device", "id", "community_encrypted"),
    ("network_device", "id", "v3_auth_key_encrypted"),
    ("network_device", "id", "v3_priv_key_encrypted"),
    ("opnsense_router", "id", "api_secret_encrypted"),
    ("opnsense_router", "id", "block_sync_api_secret_encrypted"),
    ("pairing_code", "id", "code_encrypted"),
    ("panos_firewall", "id", "api_key_encrypted"),
    ("panos_firewall", "id", "block_sync_api_key_encrypted"),
    ("platform_settings", "id", "audit_forward_webhook_auth_header_encrypted"),
    ("platform_settings", "id", "audit_forward_webhook_url_encrypted"),
    ("platform_settings", "id", "fingerbank_api_key_encrypted"),
    ("platform_settings", "id", "snmp_community_encrypted"),
    ("proxmox_node", "id", "token_secret_encrypted"),
    ("tailscale_tenant", "id", "api_key_encrypted"),
    ("unifi_controller", "id", "api_key_encrypted"),
    ("unifi_controller", "id", "block_sync_api_key_encrypted"),
    ("unifi_controller", "id", "block_sync_password_encrypted"),
    ("unifi_controller", "id", "block_sync_username_encrypted"),
    ("unifi_controller", "id", "password_encrypted"),
    ("unifi_controller", "id", "username_encrypted"),
    ('"user"', "id", "password_history_encrypted"),
    ('"user"', "id", "recovery_codes_encrypted"),
    ('"user"', "id", "totp_secret_encrypted"),
    ("wol_calendar", "id", "password_encrypted"),
)

# The same prefix the ``backup_target.config`` JSONB serializer
# stamps on every Fernet-wrapped field (see
# :mod:`app.services.backup.targets.secrets_config`). Anything
# else inside the config blob is plaintext and stays put.
_ENC_PREFIX = "__enc__:"


@dataclass(frozen=True)
class JsonbSecret:
    """One JSONB location holding Fernet ciphertext as a STRING.

    The second storage convention for secrets in this schema, and the
    one #781's first pass was structurally blind to: these are not
    ``LargeBinary`` columns and their names do not end in
    ``_encrypted``, so a sweep of the mapped metadata cannot see them.
    They still fail exactly the same way — a cross-install restore
    leaves them readable only with the source key, which on an
    appliance is gone the moment the box is reimaged.

    ``shape``:

    * ``"list"``  — the column is a JSON array of objects, and each
      key in ``keys`` on each object may hold ciphertext.
    * ``"dict"``  — the column is a single JSON object, and EVERY
      string value carrying ``prefix`` is ciphertext (``keys`` unused).

    ``prefix`` is stripped before decrypt and restored after encrypt.
    Empty means the value is bare Fernet output, which is what the
    ``platform_settings`` writers emit (``encrypt_str(...).decode()``).
    """

    table: str
    pk_col: str
    column: str
    shape: str
    keys: tuple[str, ...] = ()
    prefix: str = ""


# Every JSONB-embedded secret in the schema. Hand-maintained like
# ENCRYPTED_COLUMNS, and guarded the same way — ``test_rewrap_jsonb.py``
# fails when a new ``encrypt_str(...).decode(...)`` call site appears
# anywhere in the app without being registered here, because that idiom
# IS the act of embedding Fernet ciphertext in a JSON-friendly field.
JSONB_ENCRYPTED_FIELDS: tuple[JsonbSecret, ...] = (
    # Driver credentials (S3 secret_access_key, SCP private_key, Azure
    # account_key, …). The row's own ``passphrase_encrypted`` column is
    # covered by ENCRYPTED_COLUMNS; these are separate.
    JsonbSecret("backup_target", "id", "config", shape="dict", prefix=_ENC_PREFIX),
    # SNMPv3 auth/priv passphrases (#153).
    JsonbSecret(
        "platform_settings",
        "id",
        "snmp_v3_users",
        shape="list",
        keys=("auth_pass_enc", "priv_pass_enc"),
    ),
    # Syslog-forwarder TLS CA bundles (#159).
    JsonbSecret("platform_settings", "id", "syslog_targets", shape="list", keys=("ca_cert_pem",)),
    # APT armoured GPG key text + private-mirror passwords (#155).
    JsonbSecret(
        "platform_settings", "id", "apt_gpg_keys", shape="list", keys=("armoured_text_enc",)
    ),
    JsonbSecret("platform_settings", "id", "apt_auth", shape="list", keys=("password_enc",)),
)


@dataclass
class RewrapOutcome:
    """Per-restore counters surfaced to the operator + audit row."""

    same_install: bool = False
    rewrapped_rows: int = 0
    skipped_idempotent_rows: int = 0
    failed_rows: int = 0
    rewrapped_jsonb_fields: int = 0
    columns_visited: int = 0
    failures: list[dict[str, Any]] = field(default_factory=list)
    # True when the walk stopped early. The counters above then describe
    # what DID get rewrapped before the abort — the credential store is
    # half-migrated, which is materially different from "nothing happened"
    # and is the state the operator has to act on (#781).
    aborted: bool = False


def _fernet_from_keys(secret_key: str, credential_encryption_key: str) -> Fernet:
    """Build a Fernet using the same precedence rules as
    :func:`app.core.crypto._fernet`. ``credential_encryption_key``
    wins when set + parseable; otherwise SHA-256 over
    ``secret_key`` produces the 32-byte key material.

    Raises :class:`ValueError` only when *neither* path yields a
    usable key — in practice the SHA-256 fallback always works.
    """
    raw = (credential_encryption_key or "").strip()
    if raw:
        try:
            return Fernet(raw.encode())
        except (ValueError, Exception):  # noqa: BLE001
            # Mirrors crypto.py: malformed explicit key → fall back
            # to the derived key so the install still functions.
            pass
    digest = hashlib.sha256((secret_key or "").encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _keys_identical(
    source_secret: str,
    source_cred: str,
    dest_secret: str,
    dest_cred: str,
) -> bool:
    """Return True when the source + destination Fernet keys would
    produce identical decryption results. We compare the *derived*
    32-byte key material — the explicit-credential-key path takes
    precedence over the derived-from-secret_key path in both
    crypto.py + _fernet_from_keys above, so the comparison must
    match that precedence.
    """
    source = (source_cred or "").strip() or _derived_b64(source_secret)
    dest = (dest_cred or "").strip() or _derived_b64(dest_secret)
    return source == dest


def _derived_b64(secret_key: str) -> str:
    digest = hashlib.sha256((secret_key or "").encode()).digest()
    return base64.urlsafe_b64encode(digest).decode()


def _rewrap_value(source: Fernet, dest: Fernet, ciphertext: bytes) -> tuple[bytes | None, str]:
    """Decrypt ``ciphertext`` with the source key and re-encrypt
    with the destination key. Returns:

    * ``(new_ciphertext, "rewrapped")`` on success.
    * ``(None, "idempotent")`` when the source key fails but the
      destination key already decrypts the value — this row is
      already rewrapped (a re-run, or it was created post-restore).
    * ``(None, "failed:<short reason>")`` when neither key works —
      the row is left untouched and the failure is counted.
    """
    try:
        plaintext = source.decrypt(ciphertext)
    except InvalidToken:
        # Maybe already rewrapped — confirm by trying the dest key.
        try:
            dest.decrypt(ciphertext)
            return None, "idempotent"
        except InvalidToken:
            return None, "failed:not-decryptable-with-either-key"
    try:
        return dest.encrypt(plaintext), "rewrapped"
    except Exception as exc:  # noqa: BLE001
        return None, f"failed:re-encrypt:{exc}"


# Columns the exclude-secrets diagnostic scrub must NOT blank (#781).
#
# ``archive.py:_scrub_dump_text`` shares ENCRYPTED_COLUMNS as its
# redaction list, so widening the rewrap list widened what a diagnostic
# archive destroys. These columns are machine identity with no
# re-entry path: blanking them yields an empty bytea that satisfies
# NOT NULL, so a restore of such an archive SUCCEEDS and then
# permanently breaks the install — ``ensure_ca`` returns the existing
# row without regenerating, and every supervisor approval and cert
# re-issue fails on ``decrypt_str(b"")`` forever, with no rotate
# endpoint anywhere in the API.
#
# The bar is "can an operator put this back", not "is it important".
# ``appliance_certificate.key_encrypted`` is deliberately NOT here even
# though it is a private key: the Web-UI TLS cert has real recovery paths
# (``POST /appliance/tls/upload`` and ``/csr`` + ``/import-cert``), and a
# diagnostic archive that still carried it would defeat the point of
# scrubbing. ``appliance_ca.key_encrypted`` has no equivalent — there is
# no CA rotate endpoint anywhere in the API — which is what puts it here.
NON_REDACTABLE_COLUMNS: frozenset[tuple[str, str]] = frozenset(
    {
        ("appliance_ca", "key_encrypted"),
        ("appliance", "k3s_join_token_encrypted"),
        ("appliance", "desired_k3s_join_token_encrypted"),
        ("appliance", "kubeconfig_encrypted"),
        ("pairing_code", "code_encrypted"),
        ("acme_client_account", "account_key_encrypted"),
    }
)


# Plaintext copies of a secret that an expand/contract migration has moved
# into an ``*_encrypted`` column but not yet dropped (#296): unmapped, unread
# by the application, and still holding the pre-upgrade value. They are not
# Fernet tokens, so nothing above covers them, and an "exclude secrets"
# diagnostic archive must still not carry them. The scrubber writes NULL.
# Remove an entry in the release whose contract migration drops the column.
LEGACY_PLAINTEXT_SECRET_COLUMNS: frozenset[tuple[str, str]] = frozenset(
    {
        # #1364 — moved to ``tsig_key_secret_encrypted``.
        ("dns_server_group", "tsig_key_secret"),
        # #1502 — moved to ``url_encrypted`` / ``auth_header_encrypted``.
        # Made nullable by that migration so the scrubber's NULL restores.
        ("audit_forward_target", "url"),
        ("audit_forward_target", "auth_header"),
        ("platform_settings", "audit_forward_webhook_url"),
        ("platform_settings", "audit_forward_webhook_auth_header"),
    }
)


def redactable_columns() -> tuple[tuple[str, str, str], ...]:
    """ENCRYPTED_COLUMNS minus the machine identity that cannot be re-entered.

    The diagnostic-export scrubber consumes this, not ENCRYPTED_COLUMNS
    directly, so the rewrap list can grow without silently widening what
    an "exclude secrets" archive destroys.
    """
    return tuple(
        (table, pk, column)
        for table, pk, column in ENCRYPTED_COLUMNS
        if (table.strip('"'), column) not in NON_REDACTABLE_COLUMNS
    )


async def rewrap_secrets(
    *,
    db_url: str,
    source_secret_key: str,
    source_credential_key: str,
    dest_secret_key: str,
    dest_credential_key: str,
) -> RewrapOutcome:
    """Walk every Fernet-encrypted column + every JSONB-embedded Fernet
    string, rewrapping each value from ``source`` to ``dest``.

    No-ops cleanly when the source + destination keys are identical
    (same-install restore — counters return zero, ``same_install``
    flag set).
    """
    outcome = RewrapOutcome()
    if _keys_identical(
        source_secret_key,
        source_credential_key,
        dest_secret_key,
        dest_credential_key,
    ):
        outcome.same_install = True
        return outcome

    source_fernet = _fernet_from_keys(source_secret_key, source_credential_key)
    dest_fernet = _fernet_from_keys(dest_secret_key, dest_credential_key)

    # asyncpg uses ``postgresql://`` (or ``postgres://``) URLs —
    # SQLAlchemy's ``postgresql+asyncpg://`` is unparseable. Strip
    # the dialect suffix.
    pg_url = db_url.replace("postgresql+asyncpg://", "postgresql://", 1)

    # Every per-column rewrap commits on its own, so an abort part-way
    # through leaves the credential store HALF-migrated: the columns
    # already walked are under the destination key, the rest are still
    # under the source key. Returning the partial outcome rather than
    # raising is what makes that state reportable — the caller used to
    # discard the accumulated counters and substitute a fresh
    # ``RewrapOutcome()``, so the audit row claimed ``rewrapped_rows=0``
    # on a database where dozens of columns had in fact been rewrapped
    # (#781). ``aborted=True`` plus real counters is the honest answer.
    try:
        conn = await asyncpg.connect(dsn=pg_url)
    except Exception as exc:  # noqa: BLE001
        outcome.aborted = True
        outcome.failures.append({"reason": f"rewrap-aborted: connect failed: {exc}"})
        logger.error("backup_rewrap_connect_failed", error=str(exc))
        return outcome

    try:
        for table, pk_col, enc_col in ENCRYPTED_COLUMNS:
            outcome.columns_visited += 1
            await _rewrap_column(
                conn=conn,
                table=table,
                pk_col=pk_col,
                enc_col=enc_col,
                source=source_fernet,
                dest=dest_fernet,
                outcome=outcome,
            )
        # Then the JSONB-embedded secrets. These are a SECOND storage
        # convention — Fernet ciphertext as a JSON string rather than a
        # LargeBinary column — so nothing that sweeps the mapped metadata
        # can find them, and the first pass at #781 missed all of them.
        for spec in JSONB_ENCRYPTED_FIELDS:
            outcome.columns_visited += 1
            await _rewrap_jsonb_field(
                conn=conn,
                spec=spec,
                source=source_fernet,
                dest=dest_fernet,
                outcome=outcome,
            )
    except Exception as exc:  # noqa: BLE001
        outcome.aborted = True
        outcome.failures.append(
            {
                "reason": f"rewrap-aborted: {exc}",
                "columns_visited": outcome.columns_visited,
                "columns_total": len(ENCRYPTED_COLUMNS) + len(JSONB_ENCRYPTED_FIELDS),
            }
        )
        logger.error(
            "backup_rewrap_aborted",
            error=str(exc),
            columns_visited=outcome.columns_visited,
            rewrapped_rows=outcome.rewrapped_rows,
        )
    finally:
        await conn.close()

    return outcome


async def _rewrap_column(
    *,
    conn: asyncpg.Connection,
    table: str,
    pk_col: str,
    enc_col: str,
    source: Fernet,
    dest: Fernet,
    outcome: RewrapOutcome,
) -> None:
    """Rewrap every non-null value in one column. The whole
    column's batch runs inside a transaction so a mid-table crash
    leaves a consistent set of rewrapped + untouched rows rather
    than a half-rewrapped table.
    """
    # ``length`` filter skips the empty-bytes default columns
    # (Docker / Tailscale / UniFi / Proxmox carry empty bytea
    # defaults instead of NULL for newly-added rows).
    query = (
        f"SELECT {pk_col}, {enc_col} FROM {table} "
        f"WHERE {enc_col} IS NOT NULL AND length({enc_col}) > 0"
    )
    try:
        rows = await conn.fetch(query)
    except asyncpg.UndefinedTableError:
        # Table doesn't exist on this install — possible if the
        # operator restored from a feature module they don't have
        # enabled. Skip cleanly.
        logger.info("rewrap_table_missing", table=table, column=enc_col)
        return
    except asyncpg.UndefinedColumnError:
        # Column doesn't exist on this install — same reason.
        logger.info("rewrap_column_missing", table=table, column=enc_col)
        return

    if not rows:
        return

    async with conn.transaction():
        for row in rows:
            pk = row[pk_col.strip('"')]
            ciphertext = bytes(row[enc_col])
            new_value, status = _rewrap_value(source, dest, ciphertext)
            if status == "rewrapped":
                await conn.execute(
                    f"UPDATE {table} SET {enc_col} = $1 WHERE {pk_col} = $2",
                    new_value,
                    pk,
                )
                outcome.rewrapped_rows += 1
            elif status == "idempotent":
                outcome.skipped_idempotent_rows += 1
            else:
                outcome.failed_rows += 1
                # Track the first ten so the audit row has a
                # debuggable shape without ballooning to thousands
                # of entries on a pathological install.
                if len(outcome.failures) < 10:
                    outcome.failures.append(
                        {
                            "table": table.strip('"'),
                            "column": enc_col,
                            "pk": str(pk),
                            "reason": status,
                        }
                    )
                logger.warning(
                    "rewrap_row_failed",
                    table=table.strip('"'),
                    column=enc_col,
                    pk=str(pk),
                    reason=status,
                )


async def _rewrap_jsonb_field(
    *,
    conn: asyncpg.Connection,
    spec: JsonbSecret,
    source: Fernet,
    dest: Fernet,
    outcome: RewrapOutcome,
) -> None:
    """Rewrap every Fernet string inside one JSONB column.

    Rows are read, mutated in memory, then UPDATEd whole — there is no
    UPDATE-by-jsonb-key shortcut that plays nicely with rewrapping
    several fields of one document at once.

    A missing table or column is not an error: this list spans the whole
    schema and a restore can legitimately land on an install whose
    migrations predate one of them.
    """
    try:
        rows = await conn.fetch(
            f"SELECT {spec.pk_col} AS pk, {spec.column} AS doc FROM {spec.table}"  # noqa: S608
        )
    except (asyncpg.UndefinedTableError, asyncpg.UndefinedColumnError):
        return
    if not rows:
        return

    async with conn.transaction():
        for row in rows:
            doc = _decode_jsonb(row["doc"])
            if doc is None:
                continue
            mutated = False
            for holder, key, ciphertext in _jsonb_secret_sites(spec, doc):
                new_value, status = _rewrap_value(source, dest, ciphertext)
                if status == "rewrapped":
                    # ``status == "rewrapped"`` ⇒ new_value is bytes (see
                    # _rewrap_value), but mypy can't narrow through the
                    # string literal.
                    assert new_value is not None
                    holder[key] = spec.prefix + new_value.decode("utf-8")
                    mutated = True
                    outcome.rewrapped_jsonb_fields += 1
                elif status == "idempotent":
                    outcome.skipped_idempotent_rows += 1
                else:
                    outcome.failed_rows += 1
                    if len(outcome.failures) < 10:
                        outcome.failures.append(
                            {
                                "table": spec.table,
                                "column": f"{spec.column}.{key}",
                                "pk": str(row["pk"]),
                                "reason": status,
                            }
                        )
                    logger.warning(
                        "rewrap_jsonb_field_failed",
                        table=spec.table,
                        column=spec.column,
                        field=key,
                        pk=str(row["pk"]),
                        reason=status,
                    )
            if mutated:
                await conn.execute(
                    f"UPDATE {spec.table} SET {spec.column} = $1::jsonb "  # noqa: S608
                    f"WHERE {spec.pk_col} = $2",
                    json.dumps(doc),
                    row["pk"],
                )


def _decode_jsonb(raw: Any) -> Any:
    """asyncpg usually hands back decoded Python types; a driver or codec
    change could hand back the raw text instead, so accept both. Returns
    ``None`` for a NULL or unusable document."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return json.loads(raw)
    if isinstance(raw, bytes):
        return json.loads(raw.decode("utf-8"))
    return raw


def _jsonb_secret_sites(spec: JsonbSecret, doc: Any) -> list[tuple[dict[str, Any], str, bytes]]:
    """Every ``(containing_dict, key, ciphertext_bytes)`` in ``doc``.

    Returning the containing dict rather than a path lets the caller write
    the new value straight back, which keeps discovery and mutation in one
    shape for both document layouts.
    """
    out: list[tuple[dict[str, Any], str, bytes]] = []

    def _consider(holder: dict[str, Any], key: str) -> None:
        value = holder.get(key)
        if not isinstance(value, str) or not value:
            return
        if spec.prefix and not value.startswith(spec.prefix):
            return
        out.append((holder, key, value[len(spec.prefix) :].encode("utf-8")))

    if spec.shape == "dict":
        if isinstance(doc, dict):
            # Prefix-marked: every marked value is ciphertext whatever the
            # key. Everything else in the blob is plaintext config.
            for key in list(doc):
                _consider(doc, key)
        return out

    if isinstance(doc, list):
        for entry in doc:
            if isinstance(entry, dict):
                for key in spec.keys:
                    _consider(entry, key)
    return out
