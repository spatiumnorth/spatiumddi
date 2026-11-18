### Fixed

- The zone records view's served-apex rows now word the NS situation from the API's own fields: a placeholder name server that has an address still names the Primary NS and its missing address record, an apex NS outside the zone is no longer called unaddressed or glued to 127.0.0.1, and a zone BIND9 will not load (an in-zone NS with no address) is no longer also called served glued to 127.0.0.1 (#3840).
