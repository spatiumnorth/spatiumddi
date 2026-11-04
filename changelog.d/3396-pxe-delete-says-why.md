### Fixed

- **A refused Delete PXE profile says why (#3396).** When the server
  refuses to delete a PXE profile, the dialog now shows its reason and
  stays open, instead of staying open with nothing said. The routine
  refusal is a pool whose class restriction still names the class one of
  the profile's boot rules generates (409, #3374); a role without delete
  (403) and a profile deleted elsewhere (404) are shown the same way.
  Closing the dialog clears the reason.
