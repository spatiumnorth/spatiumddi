### Fixed

- Restoring a batch from Trash that holds a DNS zone (typically a reverse zone) no longer risks a database deadlock against a concurrent DDNS or record write on the same zones, which could fail one side with a 500. The restore now locks every zone it will write, in one fixed order, before it brings any row back (#3627).
- The same holds when the restored subnet's addresses are DHCP reservations, or only its DHCP scope is restored: the zones the re-created reservations publish into (forward and reverse) are now locked up front too, so a restore no longer deadlocks against a concurrent DHCP lease report (#3627).
