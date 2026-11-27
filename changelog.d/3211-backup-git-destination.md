### Added
- Backup destination: a git repository. Each run commits the archive under its timestamped name and pushes it, over an HTTPS token or an SSH deploy key with a pinned host key; Test connection pushes to a scratch branch, retention removes old archives in a new commit, and a failed push fails the run with a scrubbed error (#3211)
