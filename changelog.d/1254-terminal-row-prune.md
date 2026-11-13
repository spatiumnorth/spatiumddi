### Fixed
- The log prune now deletes in committed 10 000-row chunks every hour instead of one 24-hourly statement, and delivered / dead event-outbox rows, applied / superseded / failed DNS record ops and acked / failed DHCP config ops are aged out (7 days, or 30 for failures) instead of accumulating forever.
