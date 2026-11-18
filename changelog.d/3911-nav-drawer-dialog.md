### Fixed

- **The phone-width navigation drawer behaves as a modal dialog
  (#3911).** Focus moves into it and stays there, Esc closes it, and
  closing returns focus to Open navigation, which now carries
  aria-expanded. The drawer has a dialog role and the name
  "Navigation".
