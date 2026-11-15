### Fixed

- **Edit InfluxDB target and Edit audit forward target no longer put back
  another client's changes (#3926).** Both dialogs filled the form from the
  list's copy and saved every field, so a field changed elsewhere since the
  list loaded was silently reverted by an unrelated edit. They now read the
  target when they open and send only the fields you changed; both update
  endpoints apply only the fields they are sent (an audit forward target's
  kind-dependent requirements are checked on the result, not the partial
  body). A Save with nothing changed sends nothing. Stored tokens,
  passwords, webhook URLs and headers stay write-only.
- A refused delete of an InfluxDB or audit forward target (403 / 404 / 409)
  now says why and re-reads the list (#3822).
