### Fixed

- Sync DNS no longer writes a PTR or extra-zone A record the operator unticked while another row of the same address stayed ticked; the commit now carries the unticked rows (`skip_records`) and the API skips them (#2471).
