### Changed

- **The docs diagrams and the architecture pages match the code again
  (#3413).** The README architecture diagram, the seven deployment
  topologies, the DNS / DHCP / auth / IPAM / perf diagrams and the
  pages that repeat them now describe what ships: Redis 8 and BIND 9.20;
  Windows DHCP as full write-through over WinRM rather than read-only;
  every DNS server in a group as an independent authoritative copy, not
  a master and a slave; the Kubernetes chart's in-chart Redis, regular
  migrate Job and fixed worker count; Patroni marked as not supported in
  1.0; the real five-cell Platform Health strip; OIDC / SAML on their own
  authorize and callback routes, TOTP via `/auth/login/mfa`, and group
  sync for external users only; the DHCP agent long-polling its config
  with a Redis wake; and the perf client's states as the orchestrator
  actually runs them. The README diagram also gains a background, so its
  title is readable on GitHub's dark theme.
