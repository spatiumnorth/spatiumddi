### Fixed

- Appliance: after a slot upgrade `journalctl -b` was empty because journald started before the `/etc` overlay carried the persisted machine ID and wrote the journal under a second ID; `spatium-grub-render` now passes the persisted ID as `systemd.machine_id=` on every kernel command line, so it is in effect from PID 1 on each boot (#4954). A journal directory already split by an earlier upgrade is left in place and stays readable with `journalctl -D`.
