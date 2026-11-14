### Fixed

- The DNS agent no longer reuses a blocklist (RPZ) zone file damaged at the same size: reuse now checks the file's content hash, so a damaged file is rendered afresh instead of leaving the blocklist off while the server reads ok (#4080).
