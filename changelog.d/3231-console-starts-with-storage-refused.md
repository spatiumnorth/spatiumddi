### Fixed

- **The console starts when the browser refuses site data (#3231).**
  With site data blocked for the console's origin, Chrome and Edge
  refuse web storage outright, and the console stayed a blank page on
  every route, the login page included. With the storage quota full,
  every signed-in page fell to "Something went wrong". The console now
  works either way: the theme follows the system preference, and the
  sidebar's collapse, the dashboard's tab, a module's last URL and a
  dismissed VIP advisory are simply not remembered.
