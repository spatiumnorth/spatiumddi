### Fixed

- **Delete TSIG Key says a cited key cannot be deleted (#2606).** The
  dialog warned that zones citing the key "will start failing auth",
  while the server refuses that delete (409) and the reason never
  reached the dialog. It now says a cited key cannot be deleted, and a
  refused delete shows the server's reason in the dialog.
