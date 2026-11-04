### Fixed

- **A space delete writes one audit entry per object it trashes
  (#3491).** Deleting an IP space whose blocks nest collected
  everything under a nested block once for each level above it: one
  delete logged a block two levels down, its subnets, their DHCP
  scopes and reservations, and a nested subnet's auto-created reverse
  zone two or three times, and the two-person approval preview
  counted them as often (8 child blocks for a space that holds 4).
  Each object now joins the deletion once. What the delete trashes,
  its Trash entry and its restore are unchanged.
