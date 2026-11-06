### Fixed

- **A DHCP custom option row no longer takes a standard option's
  code (#3543).** In New Client Class, New DHCP Scope and the option
  templates, a custom row given the code of an option that has its own
  field (Routers, DNS Servers, NTP Servers and the others) left the
  custom list, the field kept showing its own value, and a save sent
  the row's value instead: a client class saved with DNS Servers shown
  filled stored them empty. Such a code is now refused in a custom row,
  with a hint naming the option's own field.
