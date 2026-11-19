### Fixed

- Reapplying an IPAM template (Reapply to all, or Apply with force) merges its tags and custom fields into each block or subnet instead of replacing them: the template's keys are set, and tags and custom fields the operator added that the template does not hold are kept. The Reapply dialog now says so (#4420).
