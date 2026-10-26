### Fixed

- **A signed BIND9 zone no longer freezes the rendered-config view
  (#2842).** Once a zone was inline-signed, BIND wrote binary files
  (journals, signed-zone copies) beside the zone files. Their NUL
  bytes still decode as UTF-8, so the agent pushed them, PostgreSQL
  JSONB could not store them, and the control plane refused the whole
  snapshot with a 422, leaving the console view stuck at the last
  snapshot from before signing. The agent now skips files holding a
  NUL byte and BIND's `.jnl` / `.jbk` / `.signed` / `.raw` companions,
  and the control plane drops any such file (and logs its path) rather
  than refusing the rest of the snapshot.
