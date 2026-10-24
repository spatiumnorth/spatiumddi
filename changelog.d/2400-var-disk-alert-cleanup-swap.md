### Fixed

- **A full /var no longer takes an appliance down without warning
  (#2400).** Scheduling a slot upgrade now refuses, naming the node and
  the numbers, when downloading the image onto that node's /var would
  leave it under 15% free (the kubelet's 5% eviction threshold plus its
  10% minimum reclaim). A new default-on `appliance_disk_low` alert fires
  when a node reports DiskPressure or /var is under 15% free (critical)
  or 20% free (warning), and the Fleet drilldown and Cluster node card
  show the same warning. The supervisor now reports /var's free space as
  the kubelet measures it, without ext4's 5% root reserve.
- **Upgrade images no longer pile up on /var (#2400).** The node's staged
  copy is removed as soon as the slot write ends, on failure as well as
  success. A periodic task deletes a stored upgrade image, and audits it,
  once every node it applies to (including nodes awaiting approval) runs
  that version on a committed boot and nothing is scheduled to fetch it;
  an image nothing ever scheduled is kept for 7 days.
- **The appliance no longer creates a swapfile it never uses (#2400).**
  Its fstab entry went into the /etc overlay, which systemd never reads at
  boot, so the 2 GiB file was swap only until the first reboot. Firstboot
  now removes an inactive one and stops creating it.
