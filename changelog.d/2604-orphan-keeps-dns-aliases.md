### Fixed

- **Mark as Orphan keeps an address's DNS aliases for its Restore
  (#2604).** The option is called reversible, but orphaning deleted every
  alias record of the address for good and the row's Restore re-created
  the host record only. The aliases are now withdrawn instead: they leave
  the served zone, wait in Trash under one batch per address (held back
  from the retention purge while the address is an orphan), and Restore
  publishes them again, a CNAME re-pointed at the address's current name.
  A record that took an alias's name in the meantime makes the Restore a
  409 naming it. Purging or permanently deleting the orphan deletes them.
  The dialog and both alias help lines say so.
