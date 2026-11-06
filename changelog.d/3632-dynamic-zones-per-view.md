### Fixed

- A zone that accepts dynamic updates is no longer loaded once and shared between views, so an update sent through one view is no longer answered in the other views. Each view keeps its own copy of such a zone; identical static zones still share.
