### Fixed

- **Edit template and Edit custom field no longer put back another
  client's changes (#3863).** Both dialogs filled the form from the
  list's copy and saved every field, so a template's tags, server
  groups or DDNS settings, or a custom field's options, Searchable or
  Required, set elsewhere since the list loaded were silently reverted
  by an unrelated edit. They now read the object when they open and
  send only the fields you changed.
