### Fixed

- **Approving a request whose operation refuses it at apply time now
  records the refusal instead of answering 500 (#2911).** When
  `apply()` raised anything but a permission error or a 4xx (an address
  allocated between submit and approve, a multicast subnet that an older
  build let into the queue, a driver failure), the approve rolled the
  session back and then read the approver's id off a user object the
  rollback had expired. That failed with an internal error, so the
  approver got a bare 500 and the request stayed `pending` with no
  reason, no decider and no audit row. The request is now stamped
  `approved` then `failed` with the refusal's text, the decider and
  decision time are set, the approved and failed audit rows are written,
  and the approve answers 200. This covers `/requests`,
  `/change-requests` and the Copilot approve, which share the code. A 4xx
  from `apply()` still surfaces with its status and leaves the request
  pending, as before.
