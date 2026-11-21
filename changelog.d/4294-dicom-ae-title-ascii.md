### Fixed

- **DICOM AE Titles are now held to the PS3.5 repertoire (#4294).** The
  registry accepted C1 control characters, no-break spaces and
  look-alike letters such as a Cyrillic A. A title is now 1-16
  printable ASCII characters excluding backslash, on create, update and
  CSV import, and a refusal names the offending character by code
  point. Only ASCII space is trimmed as padding. Titles already stored
  with other characters are not changed; edit them to a valid form.
