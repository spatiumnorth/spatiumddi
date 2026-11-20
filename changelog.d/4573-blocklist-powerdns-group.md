### Fixed

- Assigning a blocklist to a group that runs only PowerDNS is now refused with a 422, because PowerDNS authoritative has no RPZ and the list blocked nothing while the console showed it as applied. Existing assignments stay readable and removable and carry an `unapplied_warning`; the blocklist scope dialog shows the same warning and will not tick a new assignment on such a group. BIND9, Technitium and mixed groups are unchanged.
