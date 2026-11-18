### Fixed

- Saving a backup destination's Edit dialog without touching anything no longer turns a setting stored as null (an Azure Blob, S3 or GCS prefix) into the text "null" or a stored number into text: the dialog shows a null as an empty field and sends only the settings you changed, and the audit log no longer records a number re-sent as its text as a change.
