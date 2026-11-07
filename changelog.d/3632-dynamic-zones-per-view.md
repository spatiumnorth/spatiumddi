### Fixed

- A zone that accepts dynamic updates is no longer loaded once and shared between views, so an update sent through one view is no longer answered in the other views. Each view keeps its own copy of such a zone, and so does every primary zone of a group whose RFC 2136 grant falls to an operator TSIG key because the group has no usable key of its own; identical static zones still share.
- Turning updates off for a zone that has a copy per view no longer merges the copies back into one on a later render while a copy still holds names a client added that the control plane has not ingested; the pair stays apart until nothing beyond a render is left in either copy.
