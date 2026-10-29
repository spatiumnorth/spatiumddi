### Fixed

- **CAA values keep their quoting and escaping through every DNS driver
  (#2943).** A CAA value is stored bare (`0 issue ca.org`) or quoted
  (`0 issue "ca.org"`), and the two are one record. **Azure DNS** wrote
  the stored text after the tag as it stood, so a quoted value was
  served with its literal quotes; it now sends the value itself, and an
  entry an earlier release wrote with its quotes is recognised as the
  same record, so the next write of that record replaces it and a delete
  removes it. **Technitium** (the API driver, the importer and the agent)
  wrapped the value it read in quotes without escaping an embedded `"`
  or `\`, so such a value did not key like the stored one in drift and
  Sync with Servers; it now escapes, and the write side reads a quoted
  or bare value through one parser instead of `shlex`, so a bare value
  holding a quote or `;` stays whole. **Route 53**, **Google Cloud DNS**
  and **Cloudflare** now receive the quoted, escaped form, so a bare
  stored value is no longer sent unquoted, no longer duplicates the
  quoted value the provider hands back, and is still recognised as
  managed when its zone is emptied for deletion. **BIND9** (zone render,
  RFC 2136, and the agent) and **PowerDNS** (control plane and agent)
  quote a CAA value instead of passing it through.
- **What changes on the wire after upgrading:** for an ordinary CAA value
  nothing — the bare and quoted spellings are the same rdata, the config
  bundle (and its ETag) carries the stored value unchanged, and the agent
  compares a re-rendered zone file as a record set, so the serial does
  not move and secondaries see no transfer. Two
  kinds of stored value are served differently, and correctly: a bare
  value containing `;` (`0 issue ca.org; account=1`) used to be served
  truncated at the `;` and is now served whole, and the bare
  "no CA may issue" form `0 issue ;` used to make BIND refuse to load the
  whole zone and now loads as `0 issue ";"`. On Technitium, a bare value
  ending in a full stop now keeps it.
