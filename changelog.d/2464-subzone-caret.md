### Fixed

- **Sub-zone puts the caret before the parent suffix (#2464).** The
  dialog pre-fills ".<parent>" so the operator types the leading label,
  but the focused field kept the caret at the end, so typing "xp" made
  ".parentxp" ("contains an empty label", Add Zone disabled). The caret
  now starts at the beginning, and typing "xp" gives "xp.parent".
