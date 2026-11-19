### Fixed

- The DNS Delete Server Group dialog now says the delete also removes its trashed zones' dynamic-update grants, ACME DNS-01 accounts and DNSSEC keys (so ACME clients using those accounts must register again), not only records and pools.
