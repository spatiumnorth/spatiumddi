### Fixed

- **A dialog opened from a table row's right-click menu by keyboard
  gives focus back to the row's control (#3908).** Shift+F10 on a
  row's Edit button, then Delete…, then Esc left focus on the page
  body on IP address, IP space, DHCP scope, static assignment and DNS
  record rows, because the row itself takes no focus. Focus now goes
  back to the control that had it when the menu opened.
