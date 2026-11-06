### Fixed

- Restoring a batch from Trash that holds a DNS zone (typically a reverse zone) no longer risks a database deadlock against a concurrent DDNS or record write on the same zones, which could fail one side with a 500. The restore now locks every zone it will write, in one fixed order, before it brings any row back (#3627).
