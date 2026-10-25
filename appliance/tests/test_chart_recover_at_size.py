"""The control chart lets Postgres come back at size (#2132, #2240).

A former primary rejoining after a partition needs WAL back to where it
diverged, for ``pg_rewind`` and for streaming. With CloudNativePG's 512MB
default retention it looped for ever (#2132), so the Cluster carries a larger
``wal_keep_size``.

HOW TO RUN: python3 -m pytest appliance/tests/test_chart_recover_at_size.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent.parent
UMBRELLA = REPO / "charts" / "spatiumddi"

# CloudNativePG's own default, which #2132 outran.
CNPG_DEFAULT_WAL_KEEP_MB = 512


def _values(chart: Path) -> dict:
    return yaml.safe_load((chart / "values.yaml").read_text(encoding="utf-8"))


def _mb(q: str) -> float:
    m = re.fullmatch(r"(\d+)\s*(kB|MB|GB|TB)", q)
    assert m, f"unparsed Postgres size {q!r}"
    return int(m.group(1)) * {"kB": 1 / 1024, "MB": 1, "GB": 1024, "TB": 1024 * 1024}[m.group(2)]


def test_cnpg_keeps_wal_for_a_former_primary() -> None:
    params = _values(UMBRELLA)["postgresql"]["cnpg"]["parameters"]
    assert "wal_keep_size" in params, "postgresql.cnpg.parameters lost wal_keep_size (#2132)"
    assert _mb(params["wal_keep_size"]) > CNPG_DEFAULT_WAL_KEEP_MB
    # The Cluster renders the whole parameters map, so the default reaches the
    # CR beside whatever the supervisor's HelmChartConfig sets (shared_buffers).
    cluster = (UMBRELLA / "templates" / "cnpg-cluster.yaml").read_text(encoding="utf-8")
    assert "toYaml .Values.postgresql.cnpg.parameters" in cluster


def test_size_parser_negative_control() -> None:
    # The 512MB default must not pass the check above; a parser that read every
    # size as large would pass it vacuously.
    assert not _mb("512MB") > CNPG_DEFAULT_WAL_KEEP_MB
    assert _mb("2GB") == 2048


# #2317 — PostgreSQL's own default for max_slot_wal_keep_size is -1 (no cap).
def _gib(q: str) -> float:
    m = re.fullmatch(r"(\d+)(Mi|Gi|Ti)", q)
    assert m, f"unparsed volume size {q!r}"
    return int(m.group(1)) * {"Mi": 1 / 1024, "Gi": 1, "Ti": 1024}[m.group(2)]


def test_cnpg_caps_the_wal_a_replication_slot_keeps() -> None:
    pg = _values(UMBRELLA)["postgresql"]
    params = pg["cnpg"]["parameters"]
    assert "max_slot_wal_keep_size" in params, (
        "postgresql.cnpg.parameters has no max_slot_wal_keep_size: a slot for a standby that "
        "never follows a new primary keeps WAL until the node's /var is full (#2317)"
    )
    cap = _mb(params["max_slot_wal_keep_size"])
    keep = _mb(params["wal_keep_size"])
    # A cap at or below wal_keep_size would let a slot protect nothing more.
    assert cap > keep
    # PostgreSQL keeps max(cap, wal_keep_size) plus up to max_wal_size (1GB
    # default) since the last checkpoint: at most half the instance volume.
    max_wal = _mb(params.get("max_wal_size", "1GB"))
    assert max(cap, keep) + max_wal <= _gib(pg["persistence"]["size"]) * 1024 / 2
