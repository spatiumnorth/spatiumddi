### Fixed

- A subnet's reverse zone is now looked for in its own DNS group and the forward zone's view, so a zone of that name held by another group (Sync DNS backfill) or pinned to another view (subnet create) no longer stands in for it; the zone is made where the PTRs go (#4941).
