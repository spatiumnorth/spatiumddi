### Fixed

- **DNS Blocklists offers its writes to a user whose role grants them
  (#2698).** Pin, Unpin, Enable / Disable, Delete custom list and the sweep
  settings were disabled for everyone but a superadmin, with no reason, while
  the routes check `write` / `delete` on `dnsbl`, which the built-in Network
  Editor holds. The page now asks the same grants, and a control the caller
  may not use says why in its tooltip.
