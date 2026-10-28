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
  collision, is spelled out as a sentence. The one refusal that still
  leaves a request `pending` is a permission error about the approver
  (403), because a different approver may still approve it.

  Two edges of the same path were also wrong. An `apply()` that committed
  and then raised had already persisted the `approved` stamp, so the
  re-lock found the row no longer pending, answered a bare 400 and left it
  `approved` for good: the expiry sweep only looks at pending rows, and
  nobody could decide it. It now ends `failed` with the reason, with one
  `approved` audit row, not two. And a rejection by another approver that
  lands while the apply is failing now answers 409 rather than 400; the
  rejection stands either way.
