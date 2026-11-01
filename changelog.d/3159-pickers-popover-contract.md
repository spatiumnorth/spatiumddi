### Fixed

- **Filter-mode, Saved views, Spaces and aggregation pickers close on
  Esc and on a click elsewhere (#3159).** The address table's and DNS
  records table's Filter mode picker, the Views menu, the Dashboard's
  Spaces filter and IPAM's aggregation suggestions popover ignored Esc
  (and the Filter mode picker also ignored a click elsewhere, so it
  could sit open beside the Tools menu). They now follow the header
  menu's contract: Esc closes and returns focus to the button, a click
  elsewhere closes, and only one is open at a time. The Filter mode
  button is also named "Filter mode: <mode>" instead of by its glyph.
