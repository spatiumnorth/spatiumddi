### Fixed

- **Turning appliance registration off no longer takes DNS and DHCP down
  on every appliance (#2798).** The **Appliance registration** toggle on
  Fleet → Pairing says it refuses new pairings, but it also gated the
  heartbeat and poll of every appliance already registered: each heartbeat
  was answered 404, every supervisor read two of those as a revocation, and
  took its role services down. On a single control-plane node DNS and DHCP
  stopped within 45 s and stayed down until the toggle was switched back
  on. The flag now gates `/supervisor/register` only; registered appliances
  keep heartbeating and serving while it is off, and the toggle's text says
  so.

  The supervisor no longer treats any 404 as a revocation either. The
  control plane now marks a deliberate refusal — a revoked row, or no row
  the presented credential opens — with a 403 carrying the
  `X-Spatium-Revocation` header, and only that (or the two 403 details an
  older control plane answers for the same refusals) counts towards
  revocation. A 404 from a proxy or an unmounted router, or an unmarked
  403, is logged as `supervisor.heartbeat.refused_not_revocation` and the
  node keeps serving its last applied roles. A revoked or deleted appliance
  still stops, and a control-plane node whose row was deleted still
  re-registers (#2696).

  A heartbeat held by the long-poll while its appliance was revoked or
  deleted answered 500 instead of the revocation (#2807), so a Fleet revoke
  landed one heartbeat late. After the hold the row is re-read and refused
  exactly as a fresh heartbeat would be: 403 `revoked` or 403 `unknown`.
