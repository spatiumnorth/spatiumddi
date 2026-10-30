### Fixed

- The BIND9 agent now deletes a zone's DNSSEC key files from the persistent key directory once the zone is deleted, unsigned or moved to another group and the new config has applied cleanly, so private keys no longer linger on disk and a re-created same-name zone starts with fresh keys (#2309).
