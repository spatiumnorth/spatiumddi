"""Per-disk SMART reduction (#4731).

``read_disk_health`` reads the document the host runner writes and reduces
each disk's ``smartctl --json -a`` output. The fixtures are shaped like real
smartctl output: an NVMe drive, a SATA SSD, a spinning disk and a VM's
virtual disk, which has no ``smart_status`` at all and must come out as
"not available" rather than as healthy.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state as st

NVME = {
    "device": {"protocol": "NVMe"},
    "model_name": "ACME NVMe 1TB",
    "serial_number": "N1",
    "user_capacity": {"bytes": 1_000_204_886_016},
    "smart_status": {"passed": True},
    "temperature": {"current": 38},
    "power_on_time": {"hours": 4321},
    "nvme_smart_health_information_log": {
        "percentage_used": 12,
        "available_spare": 100,
        "available_spare_threshold": 10,
        "media_errors": 0,
    },
}
SATA_SSD = {
    "device": {"protocol": "ATA"},
    "model_name": "ACME SATA SSD",
    "rotation_rate": 0,
    "smart_status": {"passed": False},
    "temperature": {"current": 30},
    "power_on_time": {"hours": 9000},
    "ata_smart_attributes": {
        "table": [
            {"id": 5, "value": 100, "raw": {"value": 8}},
            {"id": 197, "value": 100, "raw": {"value": 2}},
            {"id": 231, "value": 7, "raw": {"value": 0}},
        ]
    },
}
HDD = {
    "device": {"protocol": "ATA"},
    "rotation_rate": 7200,
    "smart_status": {"passed": True},
    # A spinning disk's 231 means something else; must not become "wear".
    "ata_smart_attributes": {"table": [{"id": 231, "value": 7, "raw": {"value": 0}}]},
}
VM = {"device": {"protocol": "SCSI"}, "model_name": "QEMU HARDDISK", "smartctl": {"exit_status": 4}}


def _write(path: Path, disks: list[dict], *, age: int = 10, smartctl: bool = True) -> None:
    path.write_text(
        json.dumps(
            {
                "collected_at": int(time.time()) - age,
                "smartctl": smartctl,
                "disks": disks,
            }
        )
    )


@pytest.fixture
def sidecar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    p = tmp_path / "disk-smart.json"
    monkeypatch.setattr(st, "_DISK_SMART_SIDECAR", p)
    return p


def test_reduces_nvme_sata_hdd_and_vm(sidecar: Path) -> None:
    _write(
        sidecar,
        [
            {"name": "nvme0n1", "smart": NVME},
            {"name": "sda", "smart": SATA_SSD},
            {"name": "sdb", "smart": HDD},
            {"name": "vda", "smart": VM},
        ],
    )
    out = st.read_disk_health()
    assert out is not None and out["smartctl_available"] is True
    by = {d["name"]: d for d in out["disks"]}  # type: ignore[index, union-attr]
    n = by["nvme0n1"]
    assert (n["percentage_used"], n["available_spare"], n["temperature_c"]) == (12, 100, 38)
    assert (n["power_on_hours"], n["smart_passed"], n["protocol"]) == (4321, True, "nvme")
    s = by["sda"]
    assert (s["smart_passed"], s["reallocated_sectors"], s["pending_sectors"]) == (False, 8, 2)
    assert s["percentage_used"] == 93  # 100 - normalised 7
    assert by["sdb"]["percentage_used"] is None
    vm = by["vda"]
    assert vm["smart_available"] is False and vm["smart_passed"] is None


def test_unknown_is_none_never_empty(sidecar: Path) -> None:
    assert st.read_disk_health() is None  # absent
    sidecar.write_text("not json")
    assert st.read_disk_health() is None
    _write(sidecar, [{"name": "sda", "smart": HDD}], age=4 * 3600)  # stale
    assert st.read_disk_health() is None


def test_no_smartctl_is_reported_not_hidden(sidecar: Path) -> None:
    _write(sidecar, [], smartctl=False)
    out = st.read_disk_health()
    assert out is not None and out["smartctl_available"] is False and out["disks"] == []
