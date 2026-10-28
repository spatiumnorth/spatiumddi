### Fixed

- **CAA records on DigitalOcean, Linode, Vultr and Hetzner are now sent
  the way each provider's API takes them (#2959).** The four drivers
  advertised CAA but sent the whole stored value (`0 issue "ca.org"`)
  as one field. DigitalOcean takes `flags`, `tag` and `data` separately
  and Linode takes `tag` and `target` (the value, unquoted); both are now
  split on write with the shared CAA parser (`_caa.py`, #2943) and the
  canonical `<flags> <tag> "<value>"` is rebuilt on pull, so create,
  update, delete and pull key to the same record, quoted or bare.
  Vultr and Hetzner keep one value field holding the zone-file form, and
  now always get the quoted `0 issue "ca.org"`. Field names were checked
  against DigitalOcean's and Linode's OpenAPI specs. For Vultr the format
  comes from Vultr's own external-dns webhook and DNSControl's Vultr
  provider, and for Hetzner Cloud DNS from the Cloud API spec
  (presentation-format values), octodns-hetzner and community.dns. None
  of these was tested against a live account.
  A CAA record a release before this one wrote (the whole value in one
  field, quoted or not) is still found by update and delete on all four
  providers, including Hetzner's per-value path. It is not orphaned or
  duplicated, and it pulls back to the same key.
  **Behaviour change:** the record API now refuses, with a 422 before
  the record is stored, a CAA value the group's provider cannot hold.
  Before, the record was stored and then failed on every push. On Linode
  that is non-zero flags (it has no flags field) or a tag other than
  `issue` / `issuewild` / `iodef`. On Vultr it is an empty value, a value
  containing whitespace (for example `ca.org; account=1`), or one that
  needs a quote, backslash or non-ASCII escape. On DigitalOcean it is a
  value that does not parse as `<flags> <tag> <value>`.
