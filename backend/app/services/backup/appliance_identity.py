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


@dataclass
class AdoptionOutcome:
    adopted: list[dict[str, Any]] = field(default_factory=list)
    ca_replaced: bool = False
    archive_only: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


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
    (Compose, Kubernetes without an appliance) or the read fails."""
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
        return IdentitySnapshot(ca_json, rows, dns, dhcp)
    except Exception as exc:  # noqa: BLE001 — never block a restore on the capture
        logger.warning("backup_restore_identity_snapshot_failed", error=str(exc))
        return None
    finally:
        await engine.dispose()


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
            if not todo:
                return out  # the same install: the archive carries the running rows

            # The CA the adopted certificates chain to.
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

            adopted_ids = {str(a["id"]) for a in todo}
            hostnames = {str(a["hostname"]).lower() for a in todo}
            fingerprints = {a["public_key_fingerprint"] for a in todo}
            replaced: list[str] = []
            for rid, (fp, host) in existing.items():
                if rid in adopted_ids:
                    continue
                if fp in fingerprints or host in hostnames:
                    await conn.execute(
                        text("DELETE FROM appliance WHERE id = CAST(:i AS uuid)"), {"i": rid}
                    )
                    replaced.append(rid)
            out.archive_only = sorted(set(existing) - set(replaced))

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
                        "replaced_archive_rows": replaced,
                    }
                )
        names = ", ".join(sorted(str(a["hostname"]) for a in out.adopted))
        out.warnings.append(
            f"Kept this install's own appliance identity for {names}: the restore carried a "
            "different appliance registry, and replacing it would have revoked the appliance "
            "running this control plane."
        )
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
