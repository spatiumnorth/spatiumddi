### Fixed

- **Edit and Delete buttons on a DHCP group's Scopes, Client Classes
  and Option Templates, on IPAM Templates, on the DNS blocking lists
  and on Firewall aliases have accessible names (#3160).** They were
  bare pencil and bin icons, announced by a screen reader as just
  "button" (the permission gate only adds a tooltip while the button
  is refused). Each is now named for the action and the row, for
  example "Edit client class VOIP". The icon-only button guard now
  also treats a permission-gate spread as not naming a button, so
  the next one is caught.
