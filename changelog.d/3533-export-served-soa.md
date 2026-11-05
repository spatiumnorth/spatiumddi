### Fixed

- A zone file export now writes the SOA the zone is actually served with. A primary zone with no Primary NS or Admin Email was exported with the zone itself as primary master and `hostmaster.<zone>.` as the mailbox, while BIND9 serves `ns1.<zone>.` and `admin.<zone>.`; the export, the records list and the agent now share one rule. The served apex NS is noted in a comment, not written as a record (#3533).
