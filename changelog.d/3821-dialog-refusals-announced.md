### Fixed

- A refused save in most dialogs (136 error boxes in 86 files) is now drawn through the shared announced `FormError` (`role="alert"`), so a screen reader reads the server's reason when Save fails instead of staying silent; a guard test fails on a new plain red refusal box in a dialog. 19 files with open PRs are left for a follow-up (#3821).
