### Fixed

- A DNS list that was refused, failed to load or has not loaded yet no longer has a count over it: a server group's Zones tab read "0 zones" over "You don't have permission to see this group's zones", and a zone's record list, its Records tab label, a group's Records tab and its Blocking Lists tab drew "0" the same way, while the group's Servers tab said "Zone serials: no zones". Each count is drawn once its list has loaded, and a list that loaded empty still says so (#3385).
