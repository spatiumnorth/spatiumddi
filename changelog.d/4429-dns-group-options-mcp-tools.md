### Fixed

- The Operator Copilot and MCP now have tools for a DNS server group's options and DNSSEC trust anchors: `find_dns_group_options` and `find_dns_trust_anchors` (on by default), and `propose_update_dns_group_options`, `propose_add_dns_trust_anchor` and `propose_delete_dns_trust_anchor` (off by default, superadmin-only, Apply required). They share the REST routes' per-driver refusals.
