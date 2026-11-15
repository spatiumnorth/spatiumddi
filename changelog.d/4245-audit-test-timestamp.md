### Fixed

- The Test of an audit forward target sends its synthetic event with a valid RFC 3339 timestamp (ending in `Z`), not `…+00:00Z`, which strict syslog receivers and SIEMs reject.
