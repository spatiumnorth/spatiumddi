### Fixed

- Upgrade notes for 1.0.1: upgrading from 1.0.0 to 1.0.1 is supported; going back to 1.0.0 in place is not. Neither a slot rollback nor a reinstall of 1.0.0 with the pre-upgrade backup restored on it gives a working appliance (1.0.0 revokes the restored appliance about 30 seconds after the restore). Take a Full backup before upgrading and keep it. See "The way back from 1.0.1 to 1.0.0" in `docs/deployment/APPLIANCE.md` ([#4658](https://github.com/spatiumnorth/spatiumddi/issues/4658)).
