### Fixed

- **Custom Fields offers its writes to a user whose role grants them
  (#2697).** The page gated New Field, the Actions column, Edit and Delete
  on superadmin, while the routes check `write` / `delete` on
  `custom_field`, which the built-in IPAM Editor holds. The page now asks the
  same grants, so an IPAM Editor can create, edit and delete custom fields and
  a read-only Viewer still sees none of the controls.
