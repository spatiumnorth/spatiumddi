### Fixed

- A zone that accepts dynamic updates is no longer loaded once and shared between views, so an update sent through one view is no longer answered in the other views. Each view keeps its own copy of such a zone, and so does every primary zone of a group whose RFC 2136 grant falls to an operator TSIG key because the group has no usable key of its own; identical static zones still share.
