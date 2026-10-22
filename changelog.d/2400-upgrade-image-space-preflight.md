### Fixed

- **An upgrade image can no longer fill /var and get the control plane
  evicted (#2400).** Upload, import-from-GitHub and the node-side
  staging download now refuse, naming the numbers, when storing the
  image would leave under 15% of the volume free (the kubelet's 5%
  eviction trigger plus its 10% minimum reclaim). Previously the write
  succeeded and the kubelet then evicted the api, worker and supervisor
  until space was freed by hand.
