### Fixed

- **A PXE profile boots only the scopes it is bound to (#2731).**
  Each match of a bound PXE profile became a Kea client class, and
  both the DHCP agent and the config preview rendered those classes
  for the whole server. Kea evaluates such a class for every packet,
  so a PXE client in any scope on the server, including a scope with
  no profile or with another profile, was offered the bound profile's
  boot server and boot file. Each scope now lists the classes of its
  own profile, and Kea evaluates a class only for the subnets that
  list it (`only-in-additional-list` on the class,
  `evaluate-additional-classes` on the subnet, the Kea 3.0 names). A
  match with no vendor class and no architecture still matches every
  client, now of its own scopes only. An agent served by a control
  plane older than this fix renders the classes as before.
