### Fixed

- A queued delete whose scope grew since it was requested is refused at Approve with words that name what the approver can do (Reject it; the requester can cancel and submit it again) instead of telling it to cancel, which only the requester or a superadmin may do. After that refusal the Change Requests queue turns the row's Approve off with the reason and keeps Reject (#4381).
