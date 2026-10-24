### Fixed

- **A disabled integration target's old sync error no longer counts in
  its dashboard card's red total (#2221).** A target switched off while
  still holding a `last_sync_error` was counted as an error, sorted with
  the problem rows and turned its Integrations card red, for every
  integration. The summary now counts such targets in a separate
  `disabled_count`, leaves them out of the error, problem and credential
  counts, and the card greys the row's error as history.
