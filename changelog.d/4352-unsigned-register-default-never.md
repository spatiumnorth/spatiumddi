### Changed

- `APPLIANCE_UNSIGNED_REGISTER_ALLOWED` now defaults to `never`: an existing appliance must register with a signature from its own key, and an unsigned re-registration is refused even from a supervisor older than 1.0.1. Before the control plane moves to 1.1.0, upgrade every appliance still on a supervisor older than 1.0.1 to 1.0.1 or later, or delete its Fleet row and pair it again, or set `APPLIANCE_UNSIGNED_REGISTER_ALLOWED=legacy` for the upgrade window (#4352).
