### Fixed

- **A classless (RFC 2317) reverse zone under a DNS view now picks up record changes.** The BIND9 agent wrote its zone file into a nested directory it never listed, so the zone was loaded once and never reloaded: records read as applied while named kept serving the old copy. The file name now encodes `/` as `%2F`, and an existing nested file from an older render is moved over on the next render, keeping its dynamic data (#4165).
