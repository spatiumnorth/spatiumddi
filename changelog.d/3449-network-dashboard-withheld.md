### Fixed
- The Dashboard Network tab no longer shows "0" or an all-clear for panels your role may not read: the API now reports which panels it withheld (`withheld` on `/dashboards/network/summary`), and the tab shows "not visible to your role" for them instead.
