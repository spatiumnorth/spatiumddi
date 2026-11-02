### Fixed

- **The DNSSEC card no longer promises a BIND9 zone's DS within 30
  seconds (#3154).** While a signed zone had no DS to show, the card said
  "typically <30 s after signing". PowerDNS reports the DS with its sign
  op, but the BIND9 agent reports a key's DS only once BIND would publish
  it as CDS, about a day after signing on the default policy. The card
  now says so for each, and the DNS feature doc's "about two hours" is
  corrected to the same.
