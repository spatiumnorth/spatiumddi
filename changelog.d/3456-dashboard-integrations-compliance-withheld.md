### Fixed

- The Dashboard's Integrations tab now names the enabled integrations your role cannot read instead of dropping them, no longer says "No integrations are enabled yet" when some are enabled but unreadable, and qualifies its reconciler error and warning all-clears; the Compliance tab shows a refused alert rule or alert event read as refused rather than "No compliance_change rules yet" / "No compliance-change events", and the Compliance, Security and Overview panels stop re-asking reads the server refused (#3456).
