### Fixed

- **Creating a zone from a template now runs the provider-refusal gate
  (#3007).** The check that refuses a TTL the zone's hosted provider cannot
  hold (Cloudflare, Linode, Vultr, Hetzner, DigitalOcean, Azure) ran on record
  create, update, bulk create and both imports, but not on create-zone-from-
  template, so a template record the provider refuses could be stored and then
  fail at push time. Every record the template would create is now checked
  before the zone is created or pushed anywhere, and a refusal is the same 422
  with the same wording and creates nothing. The shipped templates are
  unaffected.
