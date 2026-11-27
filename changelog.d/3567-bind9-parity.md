### Added

- DNS server groups gain BIND9 `recursive-clients` and serve-stale (`stale-answer-enable`, `stale-answer-ttl`, `max-stale-ttl`) options, editable on the group Options tab and through the API and the copilot's settings read tool; PowerDNS and Technitium groups refuse them (#3567).

### Migrations

- `d7a3c5e91f20` adds `recursive_clients`, `serve_stale_enabled`, `stale_answer_ttl` and `max_stale_ttl` to `dns_server_options` (#3567).
