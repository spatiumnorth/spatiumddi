### Fixed

- Saving a DNS blocking list's scope or a zone's dynamic-updates ACL without changing anything no longer writes an audit row or wakes the agents, and when only one of the ACL's two fields changes, only that field is audited (#3738).
