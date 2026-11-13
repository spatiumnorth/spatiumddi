### Fixed

- Supervisor registration is now signed with the supervisor's own key, and an existing appliance row is re-registered only by a supervisor that holds that key. Supervisors from before the signature existed keep re-registering during an upgrade, until `APPLIANCE_LEGACY_SIGNATURE_ALLOWED=false`.
