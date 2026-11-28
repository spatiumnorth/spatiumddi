### Fixed

- A console restore no longer loses its result when it signs you out. The outcome (duration, warnings, the pre-restore safety dump path) is now recorded with the restore and shown on the Backup page after you sign in again (`GET /backup/restore/last`, superadmin), and the sign-in page says the restore was applied instead of showing a bare sign-in prompt. (#4676)
