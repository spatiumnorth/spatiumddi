### Fixed

- **The Dashboard Overview no longer reads "0 spaces · 0 subnets · healthy"
  for a user whose reads are refused (#2754).** A space, subnet, DNS or DHCP
  read the server refuses (or that fails) is shown as "—" with a line saying
  the user may not read it, the header says "status unknown" rather than
  "healthy", and the heatmap and inventory strip leave out what they cannot
  count.
- **The "Agents needing attention" tile counts what the panel of that name
  lists (#2755).** The tile left out agents whose daemon is not serving and
  agents whose zones were refused, read 0 in green, and counted the
  not-serving agent among the healthy. Tile, panel and header now share one
  `agentNeedsAttention` definition, and the header says "degraded" for an
  agent with zones refused.
