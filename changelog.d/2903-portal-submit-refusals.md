### Fixed

- **The request portal now refuses at submit what the REST create
  refuses (#2903, #2904, #2905).** An IP request for an address the
  subnet already holds, a `static_dhcp` request with no MAC, or any
  address in a multicast subnet, a reservation whose IP or MAC is
  already reserved, and a DNS record identical to one the zone already
  holds, were accepted and queued pending. They now answer the REST
  create's 409 or 422 with the reason, and no request row is created.
  A reservation whose IP matched one static and whose MAC matched
  another answered 500 at submit; it is now a 409, and the copilot's
  reservation preview no longer raises on it either. The same 500 hit
  a DNS record request whose name, type and value existed in two views.
  An approved address request with no hostname is now refused in a
  multicast subnet at apply too, so a request queued before this fix
  cannot provision one. The rules live in shared helpers the REST
  create and the portal both call.
- **The REST reservation create and update now name a duplicate IP.**
  `POST /dhcp/scopes/{id}/statics` and `PUT /dhcp/statics/{id}` with an
  IP another reservation in the same scope already holds still answer
  409, but the detail is now `IP <ip> is already reserved in this
  scope` instead of the generic `The request conflicts with existing
  data: the combination of values of 'scope_id', 'ip_address' is
  already in use.` A malformed IP keeps its `Invalid IP` 422.
