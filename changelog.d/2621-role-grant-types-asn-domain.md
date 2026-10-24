### Fixed

- **Roles: New Role no longer offers the dead grant types `asn` and `domain`, and offers `manage_domains`** — the ASN and Domains routes check `manage_asns` / `manage_domains` by exact match, so a role granting admin on `asn` or `domain` read nothing. `docs/PERMISSIONS.md` names the real types. (#2621)
