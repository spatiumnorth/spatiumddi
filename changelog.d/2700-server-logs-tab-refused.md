### Fixed

- **A DHCP or DNS server's Logs tab says it was refused and stops asking
  (#2700).** For a user without read on `server` (the DHCP Editor, for
  one) the tab read "Failed to load — try again" and asked again every 30
  seconds, writing a `denied` audit row each time. It now says the user may
  not see the log, with the server's reason, and stops after the first
  refusal. The DNS Stats tab's query analytics do the same instead of
  showing "No data in window."
