### Fixed

- **The Backup page tells a refused read it was refused (#2948).** For a
  non-superadmin, Restore Drills said "No drills have run yet." under
  Drill history and Factory Reset (and the Selective restore picker)
  said only "Failed to load section catalog.", for reads the API
  answered 403. Each now says the reader does not have permission to
  see it, with the server's reason, and a refused drill history is no
  longer polled again.
- **The restore card no longer offers a restore the restore refuses
  (#2949).** `POST /backup/manifest-preview` now also answers
  `restorable` and `restore_refusal`, from the restore's own checks:
  no database dump, no `secrets.enc`, or a `format_version` this build
  cannot read. The card shows such an archive as one that cannot be
  restored, with the reason, and keeps Apply disabled in both Full and
  Selective mode.
