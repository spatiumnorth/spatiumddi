### Fixed

- DNS Sync with Servers no longer aborts with a 500 when a provider reports a zone name SpatiumDDI refuses (a Route 53 `\057` escape, an IDN name): that zone is skipped and listed with the other skipped zones, and the rest of the sync continues. The zone-name storage rule also no longer lets a name with a trailing newline through (#4445).
