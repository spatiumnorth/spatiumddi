### Fixed

- **A logo over the limit says so, and every Settings control has an
  accessible name (#2951, #2952).** A PNG over 1 MiB was refused by
  nginx with an HTML 413 before it reached the API, and the page said
  only "Logo upload failed." The page now checks the size against the
  512 KB limit before sending and shows "Logo must be 512 KB or
  smaller", and reads any 413 without an API reason the same way.
  Separately, 48 Settings controls (text and number boxes, selects and
  all the switches) had no accessible name, because each row's label
  was a plain element beside its control. `Field` now ties its label to
  the control it wraps once, for every row, and a test walks every
  Settings section and fails on any unnamed control.
