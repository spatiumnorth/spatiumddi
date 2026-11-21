### Fixed

- The Requests page no longer offers an enabled Approve that the server then refuses: Approve is disabled, with the reason as its tooltip, when the approver lacks the permission the operation needs (for example write on DHCP reservations) or when the requester's account was deleted. A deleted-requester refusal now tells the approver to Reject the request and have the requester submit it again, instead of telling them to cancel, which only the requester can do.
