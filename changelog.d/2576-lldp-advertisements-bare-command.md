### Fixed

- **LLDP config no longer renders two lines lldpcli refuses
  (#2576).** The rendered lldpd config ended the management-address
  and capabilities advertisement lines with `enable`, which lldpcli
  rejects ("unknown command") at every lldpd start. They now render as
  the bare commands lldpcli accepts, so an advertisement turned off by
  hand is turned back on.
