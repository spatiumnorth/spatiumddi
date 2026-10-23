### Fixed

- **A DNS group of millions of records no longer OOM-kills the worker
  that renders its agents' config (#2227).** At about two million
  records in 20,000 zones in one group, every worker was killed at its
  4 GiB limit in turn and no bundle was ever stored, so agents that
  restarted never got a config. The render held the whole group: a row
  and a dict per record, then three whole serialisations (body, ETag,
  structural ETag). It now reads the records a batch of zones at a time
  (a zone larger than a batch over a server-side cursor, in chunks),
  writes them into the gzipped body as it goes, and hashes the two
  ETags from spool files that move to disk past 8 MB. Measured on a
  synthetic 20,000-zone group, peak worker RSS went from 1,016 MB to
  227 MB at 1M records and from 1,799 MB to 231 MB at 2M; what is left
  is about 4 kB per zone and twice the compressed body, not a cost per
  record. Under split-horizon views the largest zone is still held
  whole. The stored bytes and both ETags are identical to before, so
  nothing re-renders and no agent reloads on upgrade. A render the
  worker cannot survive no longer kills one worker after another: once
  two renders of a server have died mid-flight, the next records why on
  the server (`bundle_render_status = failed`, which raises the
  `agent_bundle_render_failed` alert) and holds that server for five
  minutes before trying once more. Up to two renders now run at once
  (`DNS_AGENT_BUNDLE_RENDER_SLOTS`; it was one), and a server that
  changed again while it rendered hands its slot to a waiting render
  instead of re-rendering in place, up to 50 times, while every other
  server waited. A full pass over seven servers of a 2M-record group
  took 283 s one at a time and 170 s two at a time. In a group with
  split-horizon views (the scale lab's group has one) the render also
  retires the server's queued ops, and it loaded them as rows to do it:
  with 813,000 queued for one server that alone reached 3.7 GB, twice
  the render. It now stamps them a chunk of ids at a time and loads
  none, so the same render and retire peaked at 231 MB, and the retire
  took 31 s instead of 132 s. A server that hands its slot on now comes
  back after a waiting render's next try rather than at once, which had
  let it take the slot straight back. Sizing
  per zone and per record is in `DNS.md`, "Control-plane memory for
  large groups", and in the worker's `values.yaml` comment.
