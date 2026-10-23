### Fixed

- **Agent bootstrap keys no longer asks a non-superadmin for its password (#2527).** The form is disabled with "Requires superadmin" before a password can be typed, instead of refusing the reveal (and auditing it) afterwards.
