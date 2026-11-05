### Fixed

- Documented, and pinned with a test, that BIND's limit of 64 policy zones per `response-policy` cannot be hit by blocklist assignments: all lists a group or view draws on are folded into one RPZ zone, so no assignment-time cap is needed (#3564).
