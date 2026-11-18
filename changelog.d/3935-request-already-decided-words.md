### Fixed

- Approving, rejecting or withdrawing a request that was already decided elsewhere now answers a plain 409 ("This request was already cancelled by alice at 2026-11-12 10:00 UTC") instead of a raw id and the schema state names, and the Requests page refreshes the list so the row stops offering the decision (#3935).
