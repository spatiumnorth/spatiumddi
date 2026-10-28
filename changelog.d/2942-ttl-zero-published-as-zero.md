### Fixed

- **A stored TTL of 0 is now published as 0 on every DNS driver path
  (#2942).** The record API accepts `ttl: 0` (and, with #2932, so does the
  zone-file import), but code written `ttl or default` read 0 as missing and
  published 3600 (BIND9 RFC 2136, Windows DNS over RFC 2136 and WinRM), the
  zone default (PowerDNS), or 300 (Route 53 and Google Cloud DNS, including
  the rrset-merge and delete-reduce paths that carried a live TTL of 0
  forward as the default). The database said 0 and the server served
  something else. Azure's delete-reduce path had the same flaw. The DNS
  agent's BIND9 apex fallback and Technitium's SOA and NS TTL handling, the
  AXFR read-back (which turned a served 0 into "inherit", so syncing a zone
  from its server imported the wrong TTL), the delegation preview, the ACME
  provider and client TXT paths and the PowerDNS zone importer are fixed the
  same way. Only a missing TTL (`None`) falls back to a default. A new
  `first_ttl` helper in `app/drivers/dns/base.py` is the one place that rule
  lives. Drift and Sync with Servers are unaffected either way: they match
  records by name, type and value, and never compared TTLs.
- **The record API refuses a TTL the zone's hosted provider cannot hold
  exactly (#2942).** Create, update, bulk create, zone-file import and
  spreadsheet import now answer 422, naming the accepted range, for a TTL
  outside it on a Cloudflare (30–86400; 1 is its "automatic" sentinel),
  Azure DNS (1 or more), DigitalOcean (30 or more), Hetzner (60 or more),
  Linode or Vultr (1 or more; both read 0 as "use the default") group.
  Before, such a TTL was stored and then either refused by the provider on
  every push, so the record never published, or silently published as the
  provider's default. Leaving the TTL empty is always accepted. Linode also
  rounds any TTL outside its fixed set to the nearest one; that is not
  refused.
