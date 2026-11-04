### Fixed

- **The Copilot can offer `propose_set_zone_update_acl` and
  `propose_allowlist_bgp_origin` once an operator enables them
  (#3390).** Both ship off and say an operator may switch them on,
  but they were the only `propose_*` tools registered as tools that
  write, and the Tool Catalog's save, the effective tool set and the
  chat's tool list keep only tools that do not. The Tool Catalog
  dropped them on save, so neither could ever be enabled. They are now
  registered like every other `propose_*` tool: the tool only prepares
  a proposal, and nothing changes until the operator clicks Apply.
  Both still ship off, and MCP still never offers a `propose_*` tool.
