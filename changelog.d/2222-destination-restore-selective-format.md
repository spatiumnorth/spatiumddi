### Fixed

- A backup destination's "Restore from archive" window now reads the chosen archive's database dump format before it offers Selective restore. A plain-SQL archive (for example one copied into the destination by hand) shows Selective disabled with the reason, instead of being refused only after Apply. The new read-only `GET /api/v1/backup/targets/{id}/archives/{filename}/manifest-preview` gives the same answer as the manual-restore preview, for the one archive picked rather than the whole listing.
