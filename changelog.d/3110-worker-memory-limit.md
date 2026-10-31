### Fixed

- **The chart's worker memory limit is now 2Gi, up from 1Gi (#3110).**
  Its four processes grow for about their first hour and level off near
  1 GiB, which left the old limit about 0.1 GiB for a burst of work:
  0.87 and 0.91 GiB two hours in on amd64, the limit itself after about
  40 minutes on arm64, and 1084 MiB with no limit at all. The request is
  unchanged, so scheduling is too. `make charts-lint` fails a default
  render whose worker limit is below 1.5 times that peak. The appliance
  sizes its worker limit from the node's RAM and is unchanged.
