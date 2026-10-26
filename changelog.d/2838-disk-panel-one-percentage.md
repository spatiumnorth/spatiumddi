### Fixed

- **The disk-space panel shows one free percentage (#2838).** The
  Fleet "Disk space" panel's headline rounded the free share down
  while its detail line rounded to the nearest, so one sentence could
  read "12% free ... (13%)". The headline now rounds to the nearest
  too, matching the server's detail line.
