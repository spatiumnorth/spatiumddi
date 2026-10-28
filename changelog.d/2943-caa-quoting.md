### Fixed

- **CAA values keep their quoting and escaping through every DNS driver
  (#2943).** A CAA value is stored bare (`0 issue ca.org`) or quoted
  (`0 issue "ca.org"`), and the two are one record. **Azure DNS** wrote
  the stored text after the tag as it stood, so a quoted value was
  served with its literal quotes; it now sends the value itself.
  **Technitium** (the API driver, the importer and the agent) wrapped
  the value it read in quotes without escaping an embedded `"` or `\`,
  so such a value did not key like the stored one in drift and Sync
  with Servers; it now escapes, and the write side reads a quoted or
  bare value through one parser instead of `shlex`, so a bare value
  holding a quote or `;` stays whole. **Route 53** and **Google Cloud
  DNS** now receive the quoted, escaped form they require, so a bare
  stored value is no longer sent unquoted and no longer duplicates the
  quoted value the provider hands back. **Cloudflare** matches a bare
  and a quoted value as one record. **BIND9** (zone render, RFC 2136,
  and the agent) and **PowerDNS** (control plane and agent) quote a CAA
  value instead of passing it through, where a bare
  `ca.org; account=1` lost everything after the `;` as a zone-file
  comment. The shared parser lives in `drivers/dns/_caa.py` and the
  agent's identical copy in `agent/dns/.../drivers/_caa.py`.
