### Fixed

- **CAA records on DigitalOcean, Linode, Vultr and Hetzner are now sent
  the way each provider's API takes them (#2959).** The four drivers
  advertised CAA but sent the whole stored value (`0 issue "ca.org"`)
  as one field. DigitalOcean takes `flags`, `tag` and `data` separately
  and Linode takes `tag` and `target` (the value, unquoted); both are now
  split on write with the shared CAA parser (`_caa.py`, #2943) and the
  canonical `<flags> <tag> "<value>"` is rebuilt on pull, so create,
  update, delete and pull key to the same record, quoted or bare.
  Vultr and Hetzner keep one zone-file value field and now always get
  the quoted form. Linode has no flags field, so a CAA with non-zero
  flags is refused there with a reason instead of being stored with the
  flag silently dropped. Field names for DigitalOcean (OpenAPI spec) and
  Linode (API reference) were checked against the provider docs; Vultr's
  and Hetzner's docs could not be fetched (403 / navigation shell only),
  so their quoted zone-file form follows their documented zone-file
  value convention and is unverified against the live API.
