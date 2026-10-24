### Fixed

- **Promoting a one-node appliance no longer closes the seed's web ports
  (#2450).** The first promotion raised the frontend's replicas to the
  node count, and the chart rendered the frontend's pod anti-affinity
  only above one replica, so the pod template changed and the frontend
  Deployment rolled. That roll is terminate-first (hostNetwork, host
  ports 80/443), so the seed's only frontend pod went before its
  replacement could start, and the seed refused connections on :80 and
  :443 for several seconds while the browser driving the promotion was on
  it. On the host network the anti-affinity is now rendered at one
  replica too, where it costs nothing (the host ports already allow one
  frontend pod per node), so the promotion only adds pods on the new
  nodes. A one-node appliance picks the term up with the frontend roll its
  next upgrade makes anyway.
