### Added

- DNS record changes can be scheduled: a record create (activate), update or delete (deactivate) held until a set UTC time, via `/dns/groups/{g}/zones/{z}/scheduled-changes` (list, edit, cancel). A beat task runs each due change once, through the normal record path and as the user who scheduled it, and audits both the scheduling and the result. A change fails rather than overwrite a record edited since it was scheduled, and moving its zone or record to the Trash cancels it for good. The Copilot gains `find_scheduled_dns_changes`. (#4830)
