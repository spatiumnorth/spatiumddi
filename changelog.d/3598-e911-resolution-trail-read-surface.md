### Added

- E911: the lookup trail (who asked where a device is, and what they were told) can now be read. `GET /api/v1/e911/resolution-log` (filterable by identity, time, caller, outcome and ERL, paginated) and a CSV export, a **Trail** tab on the E911 page, and default-off `find_e911_resolutions` / `count_e911_resolutions` copilot tools. It sits behind a new `e911_resolution_log` permission that no builtin role holds (a superadmin, or a wildcard `read`, reads it), separate from `e911_location`, and every read is written to the audit log.
