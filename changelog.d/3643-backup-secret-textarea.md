### Fixed

- A stored backup-target secret in a multi-line field (SCP private key, GCS service-account JSON) is no longer put in a CSS-masked textarea on edit: it shows a write-only "Set" state with Replace / Keep actions, and a textarea exists only while the operator is typing a new value. The API already returned only a redaction sentinel (#3643).
