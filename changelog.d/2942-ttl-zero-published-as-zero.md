### Fixed

- **A stored TTL of 0 is now published as 0 on every DNS driver path
  (#2942).** The record API accepts `ttl: 0` and the zone-file import
  stores it, but code written `ttl or default` read 0 as missing and
  published 3600 (BIND9 RFC 2136, Windows DNS over RFC 2136 and WinRM), the
  zone default (PowerDNS), or 300 (Route 53 and Google Cloud DNS, including
  the rrset-merge and delete-reduce paths that carried a live TTL of 0
  forward as the default). The database said 0 and the server served
  something else, which drift then reported. Azure's delete-reduce path had
  the same flaw. The DNS agent's BIND9 apex fallback and Technitium's SOA
  and NS TTL handling, the AXFR read-back used by drift, the delegation
  preview, the ACME TXT cleanup and the PowerDNS zone importer are fixed
  the same way. Only a missing TTL (`None`) falls back to a default. A new
  `first_ttl` helper in `app/drivers/dns/base.py` is the one place that
  rule lives. Cloudflare cannot represent 0 (its API takes 1 for automatic
  or 60 to 86400 seconds), so a stored 0 is sent unchanged and Cloudflare's
  own validation refuses it, rather than the driver publishing a different
  TTL than the one stored.
