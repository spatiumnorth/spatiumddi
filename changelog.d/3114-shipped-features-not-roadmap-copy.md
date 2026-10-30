### Fixed

- **Four console sentences no longer call shipped features roadmap or
  follow-up work (#3114).** Appliance Setup now points SSH keys at
  Appliance, Fleet, SSH; the WAN circuits header says circuits feed the
  service catalog and SD-WAN overlays; the Technitium (agent-managed)
  note names what the driver serves today (primary, secondary, stub and
  forward zones, DoT / DoH / DoQ) and says DNSSEC signing is BIND9 and
  PowerDNS only; and the New ASN Holder Org hint says the RDAP refresh
  job fills it for a public ASN. A circuit's term-end hint no longer
  calls the shipped `circuit_term_expiring` alert rule future work.
