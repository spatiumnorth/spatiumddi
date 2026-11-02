### Fixed

- **Applying a Copilot approve or reject proposal now says why it was refused (#3152).** The apply answered 403 "need 'approve' on 'change_request'" for every refusal, including when the approver holds that permission and the real reason was, for example, no write on the target subnet, or approving their own request. It now returns the same reason the REST approval gives. It is still a 403, and nothing else about the refusal changes.
