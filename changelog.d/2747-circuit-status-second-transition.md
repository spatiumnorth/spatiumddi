### Fixed

- **A circuit's second status change is reported while the alert for its
  first is still open (#2747).** A circuit set to suspended and then to decom
  kept one open "active → suspended" event, and the decom was not reported
  until that event was resolved by hand or after 7 days. The evaluator now
  resolves the superseded event and opens a new one for the circuit's current
  transition.
