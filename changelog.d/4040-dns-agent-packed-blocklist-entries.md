### Fixed

- **DNS agent bundle: blocklist entries ship packed (#4040).** Each
  entry was its own JSON object (~108 bytes), so three common lists
  made a 69 MB bundle that the agent parsed whole (229 MB peak) and
  kept twice on disk. An agent that advertises `packed-blocklists`
  is now sent runs of consecutive alike entries as gzip + base64
  domain lists; any other agent gets the per-entry shape. The
  rendered RPZ zone is byte-identical, entry order (first writer
  wins) is kept, and the ETag still moves with every entry.

### Migrations

- `a4040c7e91d3` — #4040, `dns_server.agent_renders_packed_blocklists`
  records whether the agent reads packed blocklist entries.
