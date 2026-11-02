### Fixed

- **Esc on a list suggestion reached with Tab no longer closes the
  whole dialog (#3157).** In the DHCP option search, the IP picker,
  the request resource picker and the tag filter, an Esc pressed on an
  entry of the open list now closes the list and keeps the dialog and
  what was typed, as an Esc in the search field already did.
  The request resource picker also no longer closes its list on a
  150 ms timer after focus moves onto an option, so that Esc no longer
  reaches the dialog.
