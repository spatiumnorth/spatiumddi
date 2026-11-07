### Fixed

- **A block's free-space, Plan allocation and aggregation answers keep
  IPv6 sizes within 64 bits and carry the exact count (#3708).** The free
  ranges' `size`, Plan allocation's `size` for each suggested subnet and
  free range, and the aggregation suggestions' `total_size` sent an IPv6
  address count past 2^63 - 1 as a bare integer, which a generated 64-bit
  client cannot decode. Each now saturates at 2^63 - 1 and has a sibling
  `size_exact` / `total_size_exact` string with the true figure, as the
  Resize previews and Find Free do (#3322). The console printed these sizes
  through a JavaScript number, so Plan allocation showed a /56 as
  "4,722,366,482,869,645,000,000" and the Allocation map's tooltips rounded
  the same way; they now print the exact figure.
