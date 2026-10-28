### Fixed

- **A cluster Rolling Upgrade no longer rolls the control plane before
  it moves the image tags (#2865).** The run holds the control chart's
  image tag and version until every node runs the target, but that
  hold covered the chart's values, not the chart: the seed's boot onto
  its new slot released the new control chart at once, and a release
  whose chart changed the api, worker or beat pods rolled them on the
  old image, the worker that drives the run with them, many minutes
  before the run moved the tags. While a run's hold is on, the seed now
  keeps the new control chart back and releases it when the hold ends:
  at the end of the run, or, for a run that failed or was aborted, when
  its hold is released. The control plane then rolls once, onto the new
  chart, image and version together. It takes effect from the first
  Rolling Upgrade into this release on: the upgrade's own run is
  driven by the release before it, and the new slot does the holding.
