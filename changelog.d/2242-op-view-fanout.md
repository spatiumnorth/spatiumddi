### Fixed

- In a DNS server group with views, each queued record op now names the view whose copy of the zone it is for, and a record change queues one op per view that renders the zone (one op, no view, in a group without views, as before). Nothing ships differently yet: the agents still take the change from the re-rendered bundle. This is groundwork for applying record changes incrementally per view; deleting a zone pinned to one view now also leaves its sibling views' queued ops alone. (#2242)
