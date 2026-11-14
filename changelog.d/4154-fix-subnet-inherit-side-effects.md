### Fixed

- **A subnet edit by a grant scoped to one subnet no longer changes the
  DNS or DDNS inherit switches as a side effect.** Naming a primary DNS
  zone, or turning DDNS on, also stores the matching inherit switch as
  off. The switches are now judged on the value the update would store,
  so such an edit is refused for a subnet-scoped grant, as a direct
  change to the switch already was. Edits by a full subnet writer are
  unchanged.
