### Fixed

- Saving a zone's dynamic-updates ACL no longer silently overwrites a change someone else made while the dialog was open. The ACL now carries a version; if it moved, the save is refused with 409 and the dialog says "Someone changed this ACL since you opened it" with a Reload button that re-reads the current entries. API clients may send `expected_version` (the `version` from `GET .../update-acl`) for the same check; leaving it out replaces unconditionally, as before. A Copilot proposal to set the ACL likewise applies only if the ACL has not changed since it was proposed.
