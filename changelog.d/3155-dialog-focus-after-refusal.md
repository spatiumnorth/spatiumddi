### Fixed

- **A refused Delete or Save in a dialog no longer leaves keyboard
  focus outside it (#3155).** A dialog whose focused submit button is
  disabled while its request runs now takes focus back onto its own
  card, so a refusal (a name in use, a reference) leaves focus inside
  the open dialog, and the reason is announced as an alert.
