### Fixed

- A backup restore is now refused (409 `restore_refused_mixed_release`) while the appliance is booted into one release but the console serving it is another, the state an acknowledged schema rollback leaves, where restoring made the older worker and beat run on the newer schema and stopped DNS changes reaching the DNS servers. The api, worker and beat `wait-for-migrate` init containers also keep waiting while a restore is running (#4678).
