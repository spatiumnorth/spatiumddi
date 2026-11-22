"""Keep the running appliance's identity across a restore (#4677).

A restore replays an archive taken on another install. ``appliance``,
``appliance_ca``, ``appliance_certificate``, ``pairing_*`` are in no backup
section, so the replay swaps them for the source install's rows. On an
appliance that is fatal: the supervisor running *this* control plane holds a
certificate signed by the CA that was just replaced, under an ``appliance_id``
the restored database has never heard of. Its heartbeats are refused as
unknown, it revokes itself after two strikes, tears the role pods down and
clears the node's role labels, and ``self-register-bootstrap`` answers 409
because the restored row has ``last_seen_at``. DNS and DHCP stop and no
console action brings them back.

The rows alive in the database **before** the replay are the ones a
supervisor is actually talking to, so they are captured first
(:func:`snapshot`) and merged back after the replay, the migration and the
rewrap (:func:`adopt`):

* the CA, when the archive's differs from the running one, so the
  supervisors' certificates verify again;
* every live appliance row the archive does not carry by id, with its
  certificate, roles, state and kubeconfig as they were. A restored row for
  the same host (same hostname, another identity: the appliance was
  reinstalled) is dropped, or the fleet would count the node twice.

* the agent identity (fingerprint, id, approval) of the live appliances' DHCP
  and DNS server rows, put on the restored rows of the same appliance, so the
  agent's next register is not read as a changed fingerprint. A server is the
  appliance's by ``appliance_id`` or, as the appliance's own agents register
  with it NULL, by its agent-based row's host being the appliance's hostname.
  Agent registers are answered 503 while the restore lock is held, so none is
  judged against a half-restored table.

A restore onto the *same* install finds its own ids in the archive and
changes nothing. Rows are copied by ``json_populate_recordset`` into the
table's own row type, so a column added later needs no change here, and bytea
and jsonb values travel exactly. Group assignments are re-pointed by group
name, because the archive's group ids are not this install's; a group the
archive does not have leaves the assignment empty.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

logger = structlog.get_logger(__name__)

# FK columns whose targets belong to the install the archive came from.
_CLEARED_COLUMNS = ("paired_via_code_id", "approved_by_user_id", "rejected_by_user_id")


@dataclass
class IdentitySnapshot:
    ca_json: str
    appliances: list[dict[str, Any]]
    dns_group_names: dict[str, str]
    dhcp_group_names: dict[str, str]
    # The live appliances' own DHCP / DNS server rows: the agent identity each
    # one registered with. Without it the restored row (install 1's, matched
    # by hostname) keeps install 1's fingerprint and the agent's next register
    # reads as a fingerprint change.
    dhcp_servers: list[dict[str, Any]] = field(default_factory=list)
    dns_servers: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AdoptionOutcome:
    adopted: list[dict[str, Any]] = field(default_factory=list)
    ca_replaced: bool = False
    archive_only: list[str] = field(default_factory=list)
    refreshed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _warning(hosts: list[str], out: AdoptionOutcome) -> str:
    names = ", ".join(sorted(set(hosts) | set(out.refreshed))) or "this install"
    return (
        f"Kept this install's own appliance identity for {names}: the restore carried a "
        "different appliance registry or certificate authority, and replacing it would have "
        "revoked the appliance running this control plane."
    )


def _engine(db_url: str):
    from app.db import _json_serializer, task_connect_args  # noqa: PLC0415

    return create_async_engine(
        db_url,
        poolclass=NullPool,
        json_serializer=_json_serializer,
        connect_args=task_connect_args(),
    )


async def snapshot(db_url: str) -> IdentitySnapshot | None:
    """Capture the live appliance identity rows. None when there are none
    (Compose, Kubernetes without an appliance). A failed read raises: the
    caller says so in the restore warnings rather than restoring into the
    outage this module exists to prevent without a word."""
    engine = _engine(db_url)
    try:
        async with engine.connect() as conn:
            rows = json.loads(
                (
                    await conn.execute(
                        text(
                            "SELECT coalesce(json_agg(row_to_json(a)), '[]'::json)::text "
                            "FROM appliance a WHERE a.revoked_at IS NULL"
                        )
                    )
                ).scalar_one()
            )
            if not rows:
                return None
            ca_json = (
                await conn.execute(
                    text(
                        "SELECT coalesce(json_agg(row_to_json(c)), '[]'::json)::text "
                        "FROM appliance_ca c"
                    )
                )
            ).scalar_one()
            dns = {
                r[0]: r[1]
                for r in (await conn.execute(text("SELECT id::text, name FROM dns_server_group")))
            }
            dhcp = {
                r[0]: r[1]
                for r in (await conn.execute(text("SELECT id::text, name FROM dhcp_server_group")))
            }
            dhcp_servers = await _live_server_rows(conn, "dhcp_server", "agent_approved", rows)
            dns_servers = await _live_server_rows(conn, "dns_server", "pending_approval", rows)
        return IdentitySnapshot(ca_json, rows, dns, dhcp, dhcp_servers, dns_servers)
    finally:
        await engine.dispose()


async def _live_server_rows(
    conn: Any, table: str, flag: str, appliances: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The agent identity of each live appliance's own server rows.

    A server belongs to an appliance by ``appliance_id`` when it is set. On a
    real appliance it usually is NOT: the local DNS / DHCP agents register
    like any other and nothing stamps the FK (the walk of #4680 found both
    rows NULL on both installs). The rule the rest of the control plane uses
    for such a row (``services/appliance/ownership.py``) applies: an
    agent-based row (``agent_id`` set) whose normalised ``host`` equals the
    hostname of exactly one live appliance. ``via`` records which rule matched
    so the carry applies the same one to the restored row."""
    from app.services.appliance.ownership import norm_host  # noqa: PLC0415

    live = {str(a["id"]): a for a in appliances}
    by_host: dict[str, list[str]] = {}
    for a in appliances:
        by_host.setdefault(norm_host(str(a["hostname"])), []).append(str(a["id"]))
    out: list[dict[str, Any]] = []
    for r in await conn.execute(
        text(
            f"SELECT name, host, appliance_id::text AS appliance_id, "  # noqa: S608
            f"agent_id::text AS agent_id, agent_fingerprint, {flag} "
            f"FROM {table} WHERE agent_fingerprint IS NOT NULL"
        )
    ):
        row = dict(r._mapping)
        if row["appliance_id"] in live:
            row["via"] = "fk"
        elif row["appliance_id"] is None and row["agent_id"] is not None:
            owners = by_host.get(norm_host(str(row["host"] or "")), [])
            if len(owners) != 1:
                continue
            row["appliance_id"] = owners[0]
            row["via"] = "host"
            row["owner_host"] = norm_host(str(live[owners[0]]["hostname"]))
        else:
            continue
        out.append(row)
    return out


_SERVER_CARRY = (
    (
        "dhcp_server",
        "dhcp_servers",
        "agent_approved",
    ),
    (
        "dns_server",
        "dns_servers",
        "pending_approval",
    ),
)


async def _carry_agent_identity(conn: Any, snap: IdentitySnapshot, live_ids: set[str]) -> list[str]:
    """Put the live agent identity on the restored server rows of an adopted
    appliance (#4677).

    The agent registers onto the restored row matched by hostname, whose stored
    fingerprint is the archive install's. DHCP then sets ``agent_approved``
    false, and the config long-poll answers pending until an operator approves
    (DNS does the same when the approval gate is on). The row of the *adopted*
    appliance (``appliance_id``, already re-pointed at the live row) with the
    live server's name takes the live fingerprint, agent id and approval, so
    the agent's register finds no change. Only those rows: the anti-hijack
    rule in the register handlers is untouched, and a hostname match to some
    other appliance's archive row is never rewritten."""
    failed: list[str] = []
    for table, attr, flag in _SERVER_CARRY:
        for srv in getattr(snap, attr):
            if str(srv["appliance_id"]) not in live_ids:
                continue
            try:
                # The restored row is the adopted appliance's by the same rule
                # the live one was: its FK, or (FK NULL) its host being the
                # appliance's hostname. A same-named row of another host is
                # some other agent's and stays as the archive had it.
                owned = "appliance_id = CAST(:app AS uuid)"
                params: dict[str, Any] = {
                    "fp": srv["agent_fingerprint"],
                    "aid": srv["agent_id"],
                    "flag": srv[flag],
                    "app": str(srv["appliance_id"]),
                    "name": srv["name"],
                }
                if srv.get("via") == "host":
                    owned = (
                        f"({owned} OR (appliance_id IS NULL AND agent_id IS NOT NULL "
                        "AND lower(rtrim(trim(host), '.')) = :host))"
                    )
                    params["host"] = srv["owner_host"]
                async with conn.begin_nested():
                    await conn.execute(
                        text(
                            f"UPDATE {table} SET agent_fingerprint = :fp, "  # noqa: S608
                            f"agent_id = CAST(:aid AS uuid), {flag} = :flag "
                            f"WHERE {owned} AND lower(name) = lower(:name)"
                        ),
                        params,
                    )
            except Exception as exc:  # noqa: BLE001 — the agent just registers afresh
                logger.warning(
                    "backup_restore_agent_identity_carry_failed", table=table, error=str(exc)
                )
                failed.append(str(srv["name"]))
    return failed


def _carry_warning(names: list[str]) -> str:
    return (
        "Could not keep the agent identity of the server(s) "
        + ", ".join(sorted(set(names)))
        + ": its agent may wait for approval after the restore."
    )


async def adopt(db_url: str, snap: IdentitySnapshot) -> AdoptionOutcome:
    """Merge the captured identity back into the restored database."""
    out = AdoptionOutcome()
    engine = _engine(db_url)
    try:
        async with engine.begin() as conn:
            existing = {
                r[0]: (r[1], r[2])
                for r in await conn.execute(
                    text("SELECT id::text, public_key_fingerprint, lower(hostname) FROM appliance")
                )
            }
            dns_ids = {
                r[0]: r[1]
                for r in await conn.execute(text("SELECT name, id::text FROM dns_server_group"))
            }
            dhcp_ids = {
                r[0]: r[1]
                for r in await conn.execute(text("SELECT name, id::text FROM dhcp_server_group"))
            }
            todo = [a for a in snap.appliances if str(a["id"]) not in existing]

            # The CA the live certificates chain to, whatever the ids say.
            snap_ca = json.loads(snap.ca_json)
            restored_ca = (
                await conn.execute(text("SELECT cert_pem FROM appliance_ca WHERE id = 1"))
            ).scalar_one_or_none()
            if snap_ca and restored_ca != snap_ca[0]["cert_pem"]:
                await conn.execute(text("DELETE FROM appliance_ca"))
                await conn.execute(
                    text(
                        "INSERT INTO appliance_ca SELECT * FROM "
                        "json_populate_recordset(null::appliance_ca, CAST(:j AS json))"
                    ),
                    {"j": snap.ca_json},
                )
                out.ca_replaced = True

            # Rows the archive carries by id keep the archive's state, but the
            # live row is what the supervisor authenticates against (state,
            # revoked_at, public key, certificate, session token), and the
            # archive's copy can predate an approval, a re-key or a revoke.
            # Another archive row holding a live fingerprint is dropped first
            # (the column is unique).
            present = [a for a in snap.appliances if str(a["id"]) in existing]
            kept_ids_now = {str(a["id"]) for a in present}
            if present:
                present_ids = [str(a["id"]) for a in present]
                for rid, (fp, _host) in existing.items():
                    if rid not in present_ids and fp in {
                        a["public_key_fingerprint"] for a in present
                    }:
                        await conn.execute(
                            text("DELETE FROM appliance WHERE id = CAST(:i AS uuid)"), {"i": rid}
                        )
                refreshed = await conn.execute(
                    text(
                        "UPDATE appliance a SET state = s.state, revoked_at = s.revoked_at, "
                        "public_key_der = s.public_key_der, "
                        "public_key_fingerprint = s.public_key_fingerprint, "
                        "cert_pem = s.cert_pem, cert_serial = s.cert_serial, "
                        "cert_issued_at = s.cert_issued_at, cert_expires_at = s.cert_expires_at, "
                        "session_token_hash = s.session_token_hash "
                        "FROM json_populate_recordset(null::appliance, CAST(:j AS json)) s "
                        "WHERE a.id = s.id AND (a.state, a.revoked_at, a.public_key_der, "
                        "a.cert_pem, a.cert_serial, a.session_token_hash) IS DISTINCT FROM "
                        "(s.state, s.revoked_at, s.public_key_der, s.cert_pem, s.cert_serial, "
                        "s.session_token_hash) RETURNING a.hostname"
                    ),
                    {"j": json.dumps(present)},
                )
                out.refreshed = sorted(str(r[0]) for r in refreshed)
            if not todo:
                # The same install: the archive carries the running rows.
                failed = await _carry_agent_identity(conn, snap, kept_ids_now)
                if failed:
                    out.warnings.append(_carry_warning(failed))
                if out.refreshed or out.ca_replaced:
                    out.warnings.append(_warning([], out))
                return out

            adopted_ids = {str(a["id"]) for a in todo}
            kept_ids = {str(a["id"]) for a in present}
            hostnames = {str(a["hostname"]).lower(): str(a["id"]) for a in todo}
            fingerprints = {a["public_key_fingerprint"]: str(a["id"]) for a in todo}
            # archive row id -> the live row that stands in for it
            replaced: dict[str, str] = {}
            for rid, (fp, host) in existing.items():
                if rid in adopted_ids or rid in kept_ids:
                    continue
                target = fingerprints.get(fp) or hostnames.get(host)
                if target is not None:
                    replaced[rid] = target
            out.archive_only = sorted(set(existing) - set(replaced) - kept_ids)

            # Free the unique fingerprint so the live row can take its place;
            # the stale row itself goes after its dependents are re-pointed.
            for rid in replaced:
                await conn.execute(
                    text(
                        "UPDATE appliance SET public_key_fingerprint = 'replaced-' || id::text "
                        "WHERE id = CAST(:i AS uuid)"
                    ),
                    {"i": rid},
                )

            for a in todo:
                row = dict(a)
                for col in _CLEARED_COLUMNS:
                    row[col] = None
                dns_name = snap.dns_group_names.get(str(row.get("assigned_dns_group_id")))
                row["assigned_dns_group_id"] = dns_ids.get(dns_name) if dns_name else None
                dhcp_name = snap.dhcp_group_names.get(str(row.get("assigned_dhcp_group_id")))
                row["assigned_dhcp_group_id"] = dhcp_ids.get(dhcp_name) if dhcp_name else None
                await conn.execute(
                    text(
                        "INSERT INTO appliance SELECT * FROM "
                        "json_populate_recordset(null::appliance, CAST(:j AS json))"
                    ),
                    {"j": json.dumps([row])},
                )
                out.adopted.append(
                    {
                        "id": str(row["id"]),
                        "hostname": row["hostname"],
                        "state": row.get("state"),
                        "assigned_roles": row.get("assigned_roles"),
                        "replaced_archive_rows": sorted(
                            r for r, t in replaced.items() if t == str(row["id"])
                        ),
                    }
                )

            # Rows hanging off the stale identity (a firewall rule scoped to the
            # node, its DNS / DHCP server rows, LLDP neighbours, collectors) move
            # to the live one; deleting the stale row would cascade them away.
            fks = (
                await conn.execute(
                    text(
                        "SELECT c.conrelid::regclass::text, a.attname FROM pg_constraint c "
                        "JOIN pg_attribute a ON a.attrelid = c.conrelid "
                        "AND a.attnum = c.conkey[1] "
                        "WHERE c.contype = 'f' AND c.confrelid = 'appliance'::regclass "
                        "AND array_length(c.conkey, 1) = 1"
                    )
                )
            ).all()
            for old_id, new_id in replaced.items():
                for table, column in fks:
                    try:
                        async with conn.begin_nested():
                            await conn.execute(
                                text(
                                    f'UPDATE {table} SET "{column}" = CAST(:n AS uuid) '  # noqa: S608
                                    f'WHERE "{column}" = CAST(:o AS uuid)'
                                ),
                                {"n": new_id, "o": old_id},
                            )
                    except Exception as exc:  # noqa: BLE001 — falls back to the cascade
                        logger.warning(
                            "backup_restore_identity_repoint_failed",
                            table=table,
                            error=str(exc),
                        )
                await conn.execute(
                    text("DELETE FROM appliance WHERE id = CAST(:i AS uuid)"), {"i": old_id}
                )
            failed = await _carry_agent_identity(conn, snap, adopted_ids | kept_ids)
            if failed:
                out.warnings.append(_carry_warning(failed))
        out.warnings.append(_warning([str(a["hostname"]) for a in out.adopted], out))
        if out.ca_replaced and out.archive_only:
            out.warnings.append(
                f"{len(out.archive_only)} appliance row(s) from the archive were kept but their "
                "certificates were signed by the archive's CA, which this install no longer "
                "uses. Any of them that still exist must be re-keyed or paired again from "
                "the Fleet page."
            )
        return out
    finally:
        await engine.dispose()
