### Fixed

- **Edit Zone, Edit View and Edit Subnet no longer put back a value saved elsewhere (#3269, #3270).**
  The three dialogs filled their form from the cached list row and sent every
  field on Save, so a Save that changed only the Color reverted a Default TTL
  someone else had saved a moment earlier. They now read the object fresh when
  they open and send only the fields you changed; a Save with no changes sends
  nothing. The zone's "Sync with server" failure dialog also no longer claims
  that only Windows DNS can pull a zone, and mentions DNS Manager only for a
  Windows DNS group.
