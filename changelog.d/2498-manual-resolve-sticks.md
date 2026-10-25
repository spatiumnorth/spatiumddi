### Fixed

- **A manually resolved alert event stays resolved (#2498).** Resolving
  an event whose subject still matched used to be undone within a tick:
  the evaluator opened a new event and paged every target again. The
  resolve is now stamped manual and suppresses re-opening until the
  subject stops matching, as the conformity engine already did.
