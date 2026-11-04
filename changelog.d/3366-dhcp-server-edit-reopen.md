### Fixed

- **Edit DHCP Server reopened right after a Save shows what was saved (#3366).**
  The server's page kept its copy of the server until its next 30 second
  refresh, so reopening Edit straight after a Save showed the old values, and
  saving that wrote them back over your change. The Save now updates the page's
  copy and the cached server lists at once.
