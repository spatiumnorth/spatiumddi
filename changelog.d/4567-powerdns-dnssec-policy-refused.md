### Fixed

- DNS: a custom DNSSEC policy is now refused (422) on a PowerDNS group instead of being stored and ignored; PowerDNS signs with fixed ECDSA P-256 / plain NSEC and does not read the policy. The built-in default and BIND9 groups are unchanged (#4567).
