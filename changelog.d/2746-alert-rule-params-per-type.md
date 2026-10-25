### Fixed

- **An alert rule's parameters are checked against its own rule type
  (#2746).** The API held every rule type to one rule per shared column, so
  "Include randomised MACs" on a New MAC seen rule could never be saved,
  counts such as "Minimum active leases" and "Stale IP count threshold" were
  refused above 100 in the words of a `threshold_percent` column the dialog
  never shows, and a 0 below a field's minimum ("Missed runs", "Flap count")
  was stored. Each value is now validated against the range or options its
  own rule type declares, and a refusal names the field's label.
