### Fixed

- Console and docs text about PowerDNS now matches what it does: a PowerDNS zone's DNSSEC keys are never rolled (the DNSSEC card, the manual-rollover note and the API docstring said they rotate on pdns's schedule), the control plane owns the SOA serial, LUA records are enabled by the global `enable-lua-records` setting rather than zone metadata, the group form's catalog-zone checkbox is no longer labelled BIND9-only, and the DNSSEC policy picker says PowerDNS ignores the policy.
