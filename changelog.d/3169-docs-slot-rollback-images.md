### Fixed

- **Troubleshooting now covers pods stuck in `ErrImageNeverPull` after an appliance slot rollback (#3169).** k3s imports its image tarballs from the shared `/var`, which holds the newest upgraded slot's set, so a rolled-back slot can come up without its own images. A new recipe in `docs/TROUBLESHOOTING.md` restores them from the slot's own filesystem, and the appliance guide no longer says that booting the previous slot leaves the node exactly as it was.
