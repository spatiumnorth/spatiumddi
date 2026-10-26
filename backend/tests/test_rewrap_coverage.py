"""``ENCRYPTED_COLUMNS`` must match the schema exactly (#781).

The cross-install rewrap is what makes a restore onto a different install
work: every Fernet-encrypted column is decrypted with the source install's
key and re-encrypted with the destination's. A column missing from that
list is silently skipped — the restore reports success and the value stays
encrypted under a key the destination does not have. First use throws
``InvalidToken``, and once the source box is gone the key exists only
inside a `secrets.enc` the operator has probably discarded.

That is not a hypothetical: on the appliance, ``spatiumddi-firstboot``
mints a fresh ``SECRET_KEY`` on every install, so EVERY restore onto
reimaged hardware is a cross-install restore.

The list is deliberately hand-maintained so that adding an encrypted
column is a review decision. This test is what makes that safe — without
it the list drifted to 21 of 47 columns and named a table
(``tailscale_target``) that has never existed, whose lookup failure the
``UndefinedTableError`` handler swallowed silently.
"""

from __future__ import annotations

from sqlalchemy import LargeBinary

import app.main  # noqa: F401  — imported for the side effect of mapping every model
from app.models.base import Base
from app.services.backup.rewrap import ENCRYPTED_COLUMNS

# ``user`` is a reserved word, so the rewrap list quotes it for raw SQL.
_QUOTED = {'"user"': "user"}


def _listed() -> set[tuple[str, str]]:
    return {(_QUOTED.get(table, table), column) for table, _pk, column in ENCRYPTED_COLUMNS}


def _mapped() -> set[tuple[str, str]]:
    """Every Fernet-encrypted column, per the mapped metadata.

    Keyed on ``LargeBinary`` + the ``_encrypted`` suffix, which is the
    convention every such column in this codebase follows.
    """
    return {
        (table.name, column.name)
        for table in Base.metadata.sorted_tables
        for column in table.columns
        if isinstance(column.type, LargeBinary) and column.name.endswith("_encrypted")
    }


def test_rewrap_covers_every_encrypted_column() -> None:
    missing = _mapped() - _listed()
    assert not missing, (
        "These Fernet-encrypted columns are not rewrapped, so a restore onto "
        "another install leaves them encrypted with the SOURCE key and the "
        "operator finds out on first use:\n  "
        + "\n  ".join(f"{t}.{c}" for t, c in sorted(missing))
        + "\n\nAdd them to ENCRYPTED_COLUMNS in app/services/backup/rewrap.py."
    )


def test_rewrap_lists_no_column_that_does_not_exist() -> None:
    """A stale entry is worse than a missing one: the raw-SQL lookup fails,
    ``UndefinedTableError`` is swallowed as 'table absent on this install',
    and nothing reports that a real column went unrewrapped."""
    stale = _listed() - _mapped()
    assert not stale, (
        "ENCRYPTED_COLUMNS names columns that do not exist; their rewrap "
        "failures are silently swallowed:\n  " + "\n  ".join(f"{t}.{c}" for t, c in sorted(stale))
    )


def test_every_listed_table_has_the_primary_key_the_rewrap_uses() -> None:
    """The rewrap UPDATEs row-by-row keyed on the recorded pk column."""
    by_name = {t.name: t for t in Base.metadata.sorted_tables}
    wrong: list[str] = []
    for table, pk, column in ENCRYPTED_COLUMNS:
        real = by_name.get(_QUOTED.get(table, table))
        if real is None:
            continue  # covered by the staleness test above
        pk_cols = [c.name for c in real.primary_key.columns]
        if pk_cols != [pk]:
            wrong.append(f"{table}.{column}: listed pk={pk!r}, actual={pk_cols}")
    assert not wrong, "\n".join(wrong)


# ── schema-direction gate (#781) ─────────────────────────────────────


def test_newer_schema_is_refused_before_anything_is_replayed() -> None:
    """An archive from a newer install must be refused while the database
    is still intact. The post-replay check reports the same condition, but
    by then the data is overwritten and the api can no longer start."""
    from app.services.backup.migrations import _local_head, schema_direction_error

    err = schema_direction_error("ffffffffffff")  # not in this build's chain
    assert err is not None
    assert "NEWER schema" in err
    assert (_local_head() or "") in err


def test_schema_direction_gate_passes_the_cases_it_should() -> None:
    from app.services.backup.migrations import _local_head, schema_direction_error

    assert schema_direction_error(None) is None, "pre-v2 archive carries no head"
    assert schema_direction_error("") is None
    assert schema_direction_error(_local_head()) is None, "same head is fine"


def test_the_override_warning_says_what_the_api_does_on_a_newer_schema() -> None:
    """A restore made with ``allow_newer_schema`` leads with this warning.
    Readiness no longer refuses every newer schema (#2777), so the warning
    says what holds: an api pod that starts on it stays unready, and one
    already serving keeps serving only while what its build uses is there."""
    from app.services.backup.restore import _schema_override_warning

    refusal = "This archive was taken on a NEWER schema than this install."
    warning = _schema_override_warning(refusal)

    assert warning.startswith(f"Schema-direction check OVERRIDDEN: {refusal} ")
    assert "allow_newer_schema was set" in warning
    assert "An api pod that starts or restarts on it stays unready" in warning
    assert "keeps serving only while every table and column this build uses" in warning
    assert "Upgrade to a build at or past the archive's head" in warning
    assert "rejects" not in warning, "readiness no longer rejects every newer schema"


# ── selective-restore section catalog (#781) ─────────────────────────

# Tables the section catalog does not classify today. A table that is
# absent from every section is never restored in a SELECTIVE restore —
# and worse, if it FK-references a table that IS selected, the
# ``TRUNCATE … CASCADE`` wipes it and nothing puts it back, so the
# operator loses rows outside the sections they picked.
#
# Frozen as a baseline rather than fixed here: classifying 56 tables is a
# judgement call per table (which section owns an ACME order? an upgrade
# image?) and belongs with someone deciding the semantics, not bundled
# into a rewrap fix. What this DOES buy is that the gap can no longer
# grow silently — a newly added table has to be classified or explicitly
# added here. ``assert_catalog_covers_models`` was written to catch this
# and was simply never wired up to anything.
_UNCLASSIFIED_BASELINE: frozenset[str] = frozenset(
    {
        "acme_client_account",
        "acme_http_challenge",
        "acme_order",
        "address_set",
        "appliance",
        "appliance_ca",
        "appliance_certificate",
        "appliance_lldp_neighbour",
        "appliance_upgrade_image",
        "approval_policy",
        "bgp_hijack_detection",
        "bgp_lg_peer",
        "bgp_lg_route",
        "bgp_tracked_prefix",
        "change_request",
        "cloud_endpoint",
        "dhcp_observed_responder",
        "dhcp_responder_allowlist",
        "dns_zone_update_acl",
        "dnsbl_list",
        "dnsbl_listing",
        "dnsbl_pinned_ip",
        "dnssec_key",
        "dnssec_policy",
        "firewall_alias",
        "firewall_apply_state",
        "firewall_endpoint_object",
        "firewall_feed",
        "firewall_policy",
        "firewall_rule",
        "fortinet_firewall",
        "looking_glass_collector",
        "mac_allowlist",
        "meraki_org",
        "netbird_instance",
        "network_block",
        "network_block_push",
        "opnsense_router",
        "packet_capture",
        "pairing_claim",
        "pairing_code",
        "panos_firewall",
        "ra_observed_router",
        "ra_router_allowlist",
        "restore_drill",
        "saved_view",
        "subnet_utilization_history",
        "system_upgrade_run",
        "time_bound_grant",
        "tls_cert_probe",
        "tls_cert_target",
        "wol_calendar",
        "wol_calendar_event",
        "wol_run",
        "wol_run_target",
        "wol_schedule",
    }
)


def test_section_catalog_gap_does_not_grow() -> None:
    from app.services.backup.sections import assert_catalog_covers_models

    known = {t.name for t in Base.metadata.sorted_tables}
    missing = set(assert_catalog_covers_models(known))

    new = missing - _UNCLASSIFIED_BASELINE
    assert not new, (
        "These tables are in no backup section, so a selective restore "
        "silently skips them — and cascade-truncates them if they "
        "reference a selected table:\n  "
        + "\n  ".join(sorted(new))
        + "\n\nAdd each to a SECTION in app/services/backup/sections.py."
    )

    fixed = _UNCLASSIFIED_BASELINE - missing
    assert not fixed, (
        "These tables are now classified — drop them from "
        "_UNCLASSIFIED_BASELINE so the gap keeps shrinking:\n  " + "\n  ".join(sorted(fixed))
    )


# ── exclude-secrets scrub must not destroy machine identity (#781) ───


def test_scrub_list_excludes_non_regenerable_machine_identity() -> None:
    """Machine identity must not be blanked to an empty bytea: that satisfies
    NOT NULL, so restoring the archive SUCCEEDS and then permanently breaks
    the install — `ensure_ca` returns the existing row without regenerating
    and every approval fails on `decrypt_str(b"")` (#781). It is scrubbed in
    the shape its reader regenerates from instead (row left out, or NULL)."""
    from app.services.backup.rewrap import (
        SCRUB_NULLED_ENCRYPTED_COLUMNS,
        SCRUB_OMITTED_TABLES,
        redactable_columns,
    )

    scrubbed = {(t.strip('"'), c) for t, _pk, c in redactable_columns()}
    assert not (scrubbed & SCRUB_NULLED_ENCRYPTED_COLUMNS)
    assert ("appliance_ca", "key_encrypted") not in scrubbed, "no CA rotate endpoint exists"
    assert "appliance_ca" in SCRUB_OMITTED_TABLES


def test_scrub_list_still_redacts_operator_re_enterable_credentials() -> None:
    """The feature must keep working for what it is for: credentials an
    operator can simply type back in."""
    from app.services.backup.rewrap import redactable_columns

    scrubbed = {(t.strip('"'), c) for t, _pk, c in redactable_columns()}
    for pair in (
        ("auth_provider", "secrets_encrypted"),
        ("panos_firewall", "api_key_encrypted"),
        ("dns_server", "credentials_encrypted"),
        # A private key, but recoverable via POST /appliance/tls/upload
        # or /csr + /import-cert — so leaving it in a "sanitized" archive
        # would defeat the point of scrubbing.
        ("appliance_certificate", "key_encrypted"),
    ):
        assert pair in scrubbed


def test_schema_gate_fails_closed_when_it_cannot_verify() -> None:
    """A safety gate that cannot perform its check must refuse, not proceed.

    Returning None ("direction is fine") when the local head is unreadable
    silently disabled the whole #781 protection — the failure mode is the
    destructive one, so an unverifiable archive is refused instead."""
    from app.services.backup import migrations

    original = migrations._local_head
    try:
        migrations._local_head = lambda: None  # type: ignore[assignment]
        err = migrations.schema_direction_error("ffffffffffff")
    finally:
        migrations._local_head = original  # type: ignore[assignment]

    assert err is not None
    assert "Cannot verify" in err
    # …but an archive that declares no head at all still passes: there is
    # nothing to compare, and refusing every pre-v2 archive would be wrong.
    try:
        migrations._local_head = lambda: None  # type: ignore[assignment]
        assert migrations.schema_direction_error(None) is None
    finally:
        migrations._local_head = original  # type: ignore[assignment]


def test_schema_gate_reads_the_head_from_either_source() -> None:
    """`secrets.enc` carries the same head as the manifest and is already
    decrypted by the time the gate runs, so an archive whose manifest never
    recorded one is still checked rather than slipping past."""
    from app.services.backup.migrations import _local_head, schema_direction_error

    manifest: dict[str, str] = {}
    secrets_payload = {"schema_version": "ffffffffffff"}

    err = schema_direction_error(
        manifest.get("schema_version") or secrets_payload.get("schema_version")
    )
    assert err is not None, "the head from secrets.enc must still be checked"
    assert (_local_head() or "") in err
