### Fixed

- Approving a change request no longer risks a database deadlock against a concurrent DNS or IPAM write: the approval's audit entry is now recorded after the approved operation runs, not before it, matching the lock order every other path uses. The audit log therefore shows the change first, then the approval and execution entries.
