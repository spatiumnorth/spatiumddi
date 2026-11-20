### Changed

- An appliance's re-registration is now checked against the supervisor version it last reported: an unsigned one is accepted only for an appliance last seen on a version before 1.0.1, is recorded in the audit log and counts against the registration attempt budget. The new `APPLIANCE_UNSIGNED_REGISTER_ALLOWED` setting (`legacy`, the default; `never` refuses every unsigned re-registration) is separate from `APPLIANCE_LEGACY_SIGNATURE_ALLOWED`. 1.1.0 will default to `never`.
