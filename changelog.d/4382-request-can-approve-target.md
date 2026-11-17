### Fixed

- The Requests page no longer offers an enabled Approve that the server then refuses: for an IP address request in a subnet the approver's write grant does not reach, or a subnet request for a block they cannot write, the row's Approve is disabled and says why, because it now runs the same per-object check the approval does.
