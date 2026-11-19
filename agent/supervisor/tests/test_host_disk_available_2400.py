"""#2400 — the /var reading carries what the kubelet's eviction signal sees.

``read_host_disk_partitions`` reported ``total`` and ``used`` (= blocks -
bfree), so the only free figure the control plane could derive was
``total - used`` = bfree. ext4 keeps 5 % reserved for root by default and
the kubelet's ``nodefs.available`` is bavail, so that figure overstated the
headroom by the reserve — ~750 MB on a 15 GB ``/var``, which is the margin
the issue's node ran out of. ``available_bytes`` is f_bavail.
"""

from __future__ import annotations

import os

from spatium_supervisor import appliance_state


def test_available_bytes_is_bavail_not_bfree(monkeypatch) -> None:
    frsize = 4096
    blocks = 3_840_000  # ~15.7 GB
    bfree = 500_000
    bavail = bfree - blocks * 5 // 100  # the 5 % root reserve

    def fake_statvfs(path: str) -> os.statvfs_result:
        return os.statvfs_result(
            (frsize, frsize, blocks, bfree, bavail, 0, 0, 0, 0, 255)
        )

    monkeypatch.setattr(appliance_state, "_DISK_TARGETS", (("/var", "Data", "/x"),))
    monkeypatch.setattr(appliance_state.os, "statvfs", fake_statvfs)

    [entry] = appliance_state.read_host_disk_partitions()
    assert entry["total_bytes"] == blocks * frsize
    assert entry["used_bytes"] == (blocks - bfree) * frsize
    assert entry["available_bytes"] == bavail * frsize
    assert entry["available_bytes"] < entry["total_bytes"] - entry["used_bytes"]
