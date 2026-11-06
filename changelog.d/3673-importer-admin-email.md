### Fixed

- The DNS importers (BIND9, PowerDNS, Technitium) now hold a zone's SOA mailbox (RNAME) to the rule Add Zone applies to the Admin Email. One it would refuse, such as `hostmaster.under_score.example.com` or `john\.doe.example.com`, is no longer stored for the agent to drop and replace with `admin.{zone}` unannounced: the zone's Admin Email is left empty and the preview warns, per zone, that the RNAME was not kept and why. (#3673)
