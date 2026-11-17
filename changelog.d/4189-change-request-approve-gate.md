### Fixed

- The Change Requests queue now disables Approve, with the reason (for example "Permission denied: need 'delete' on 'subnet'"), on a request the signed-in approver lacks the operation's own permission to approve, instead of refusing only after the confirmation. The API reports `can_approve` and `approve_blocked_reason` per request, from the same check the approve endpoint makes.
