### Fixed

- **Approving a request whose operation refuses it at apply time now
  records the refusal instead of answering 500 or leaving the request
  pending (#2911).** When `apply()` raised a plain error (an address
  allocated between submit and approve, a multicast subnet that an older
  build let into the queue, a driver failure), the approve rolled the
  session back and then read the approver's id off a user object the
  rollback had expired. That failed with an internal error, so the
  approver got a bare 500 and the request stayed `pending` with no
  reason, no decider and no audit row. The request is now stamped
  `approved` then `failed` with the refusal's text, the decider and
  decision time are set, the approved and failed audit rows are written,
  and the approve answers 200. This covers `/requests`,
  `/change-requests` and the Copilot approve, which share the code, and
  each is now tested.

  **Behaviour change:** a 4xx from `apply()` now ends the same way. It
  used to answer with its status and leave the request `pending`, which
  told the requester nothing, and whether a refusal ended `failed` or
  stayed `pending` depended on which exception the operation happened to
  raise. For example, a DHCP reservation whose MAC was reserved elsewhere
  after submit stayed pending, while an IP address taken after submit
  ended failed. Now the request ends `failed` and the requester reads the
  reason on the portal. A structured detail, such as the IPAM name
  collision, is spelled out as a sentence. The same applies when the
  preview that re-runs at approve time refuses (the target is gone, the
  subnet is no longer empty): that used to answer 409 and leave the
  request pending, and it now ends `failed` with the reason.

  Two outcomes still leave a request `pending`. A permission error about
  the approver answers 403, because a different approver may still
  approve it. And on a `/change-requests` row, a re-run preview that
  still succeeds but describes a different scope from the one the
  approver reviewed answers 409, because the change is still possible
  but is not what was approved.

  Two edges of the same path were also wrong. An `apply()` that committed
  and then raised had already persisted the `approved` stamp, so the
  re-lock found the row no longer pending, answered a bare 400 and left it
  `approved` for good: the expiry sweep only looks at pending rows, and
  nobody could decide it. It now ends `failed` with the reason, with one
  `approved` audit row, not two. And a rejection by another approver that
  lands while the apply is failing now answers 409 rather than 400; the
  rejection stands either way.
