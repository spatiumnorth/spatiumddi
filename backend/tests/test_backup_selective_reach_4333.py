"""The selective-restore warning is derived from the restore's own closure (#4333)."""

import pytest

from app.services.backup import sections as sec


def test_dns_reach_names_ip_addresses():
    reach = sec.also_restored_by_section("dns")
    assert "ip_address" in reach["ipam"]


def test_reach_matches_cascade_closure():
    for s in sec.SECTIONS:
        own = set(s.tables)
        flat = {t for ts in sec.also_restored_by_section(s.key).values() for t in ts}
        assert flat == sec.cascade_closure(own) - own


def test_adding_a_table_to_a_section_changes_reach():
    from sqlalchemy import Column, ForeignKey, Integer, Table

    from app.models.base import Base

    dns_table = next(iter(sec.SECTIONS_BY_KEY["dns"].tables))
    pk = list(Base.metadata.tables[dns_table].primary_key.columns)[0]
    t = Table("zz_reach_probe", Base.metadata, Column("id", Integer, primary_key=True))
    t.append_column(Column("ref", pk.type, ForeignKey(f"{dns_table}.{pk.name}")))
    try:
        before = sec.also_restored_by_section("dns")
        assert "zz_reach_probe" in {x for ts in before.values() for x in ts}
    finally:
        Base.metadata.remove(t)
    after = sec.also_restored_by_section("dns")
    assert "zz_reach_probe" not in {x for ts in after.values() for x in ts}


@pytest.mark.asyncio
async def test_catalog_endpoint_exposes_also_restores():
    from app.api.v1.backup.router import list_backup_sections

    cat = await list_backup_sections(current_user=None)  # type: ignore[arg-type]
    dns = next(s for s in cat.sections if s.key == "dns")
    ipam = next(x for x in dns.also_restores if x.key == "ipam")
    assert "ip_address" in ipam.tables
