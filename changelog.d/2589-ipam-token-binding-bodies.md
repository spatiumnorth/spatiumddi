### Fixed

- **An API token bound to specific subnets or zones is held to them on the
  IPAM imports, the exports, subnet domains and subnet bulk edit.** The router check that
  holds such a token to its subnets reads ids from the path and the query
  string, and these routes take theirs from a form or a JSON body, or are
  handed a whole block or space. The address import preview and commit now
  refuse a subnet the token is not bound to. The whole-space import preview,
  JSON preview and commit refuse a token bound to subnets. `GET
  /ipam/export` and `/ipam/export.pdf` with `space_id` or `block_id` refuse
  one too, since the export carries every subnet and address in the
  container; it exports its own subnets with `subnet_id`. And
  `POST /ipam/subnets/{id}/domains` accepts only a zone the token holds a
  grant on, the same rule the address and subnet writes already follow.
  Two more found by the new guard: `POST /ipam/subnets/bulk-edit` refuses a
  batch naming a subnet the token is not bound to, and the bulk-allocate
  preview checks its `dns_zone_id` as the commit does.
  Sessions, tokens without resource grants and wildcard subnet grants are
  unaffected. The route sweep now runs the exports with each container id,
  and fails on any IPAM write whose body carries a zone or subnet id
  without a recorded check.
