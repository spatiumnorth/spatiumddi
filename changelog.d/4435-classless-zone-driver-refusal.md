### Fixed

- A classless (RFC 2317) reverse zone name is now refused with a 422 on a group whose driver cannot serve it, instead of being accepted and never populated (the PowerDNS agent 404s every request on a name holding `/`). Only BIND9 serves them; the check covers zone create, rename, create from template, zone move (preview and commit), the zone-file importer, and adding or moving a server into a group that already holds one.
